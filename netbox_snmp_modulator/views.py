import re
import uuid
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.cache import cache
from django.http import QueryDict
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext as _
from django.urls import reverse
from django.views import View

from dcim.filtersets import DeviceFilterSet
from dcim.models import Device

from . import client

USE_PERM = "netbox_snmp_modulator.use_modulator"
RUN_PERM = "netbox_snmp_modulator.run_modulator"

# Above this many devices the bulk page lists only the next batch.
LIST_MAX = 500
# Presets: devices not modulated for this many days.
STALE_DAYS = 30
# Per-device estimate before a run has measured its own average.
EST_SECONDS = 30
# Device list parameters that aren't filters.
_NON_FILTER_PARAMS = {"page", "per_page", "sort", "ordering", "export", "return_url", "tab", "embedded"}


def plugin_config():
    return settings.PLUGINS_CONFIG.get("netbox_snmp_modulator", {})


def _device_ip(device):
    if not device.primary_ip4:
        return None
    return str(device.primary_ip4.address.ip)


def _pin_tag():
    return plugin_config().get("pin_tag") or None


def _pinned_ids(ids):
    tag = _pin_tag()
    if not tag or not ids:
        return set()
    return set(Device.objects.filter(pk__in=ids, tags__slug=tag).values_list("pk", flat=True))


_RULE_MATCH_LABELS = {
    "device_type.manufacturer.slug": "Manufacturer",
    "device_type.model": "Model",
    "device_type.slug": "Device type",
    "device_type.part_number": "Part number",
    "role.slug": "Role",
    "platform.slug": "Platform",
    "site.slug": "Site",
    "site.region.slug": "Region",
    "name": "Name",
    "tags": "Tag",
}


def _rule_match_label(key):
    if key.startswith("custom_fields."):
        return key.split(".", 1)[1]
    return _RULE_MATCH_LABELS.get(key, key)


_RULE_LITERAL = re.compile(r"^[\w\-/ ]+(\|[\w\-/ ]+)*$")


def _rule_values(v):
    """Match values as (text, regex?) — plain alternations ("ani|ana") become
    a list of plain values, anything else stays a regex."""
    out = []
    for x in v if isinstance(v, list) else [v]:
        x = "" if x is None else str(x)
        if _RULE_LITERAL.match(x):
            out += [(p, False) for p in x.split("|")]
        else:
            out.append((x, True))
    return out


def _rule_modules(m):
    """{add, try, block} lists of one modules section (normal or fast)."""
    m = m or {}
    return {k: list(m.get(k) or []) for k in ("add", "try", "block")}


def _rule_polling(m):
    m = m or {}
    if m.get("interval") or m.get("timeout"):
        return f"{m.get('interval') or '—'} / {m.get('timeout') or '—'}"
    return ""


def _rule_auth(auth):
    """("try", [profiles]) / ("use", profile or None = no SNMP) / None."""
    if not auth:
        return None
    if "use" in auth:
        return {"kind": "use", "profiles": [auth["use"]] if auth["use"] else []}
    return {"kind": "try", "profiles": list(auth.get("try") or [])}


def _rule_hooks(rule):
    out = []
    for when in ("on_success", "on_fail"):
        h = rule.get(when) or {}
        for key, sign in (("add_tag", "+"), ("remove_tag", "−")):
            out += [f"{when.replace('_', ' ')}: {sign}{t}" for t in h.get(key) or []]
        out += [f"{when.replace('_', ' ')}: notify {n}" for n in h.get("notify") or []]
    return out


def rules_context(data):
    """Rows and the "for every device" info of a /rules response."""
    rows = []
    for i, r in enumerate(data.get("rules") or [], 1):
        mods = r.get("modules") or {}
        rows.append({
            "n": i,
            "name": r.get("name") or f"#{i}",
            "match": [(_rule_match_label(k), k, _rule_values(v)) for k, v in (r.get("match") or {}).items()],
            "normal": _rule_modules(mods),
            "fast": _rule_modules(mods.get("fast")),
            "polling": _rule_polling(mods),
            "polling_fast": _rule_polling(mods.get("fast")),
            "auth": _rule_auth(r.get("auth")),
            "hooks": _rule_hooks(r),
        })
    defaults = data.get("defaults") or {}
    info = {
        "defaults": _rule_modules(defaults.get("modules")),
        "default_auth": _rule_auth(defaults.get("auth")),
        "module_field": data.get("module_field"),
        "fast_module_field": data.get("fast_module_field"),
        "module_policy": data.get("module_policy"),
        "auth_policy": data.get("auth_policy"),
        "polling": f"{data.get('default_interval') or '—'} / {data.get('default_timeout') or '—'}",
        "polling_fast": f"{data.get('fast_default_interval') or '—'} / {data.get('fast_default_timeout') or '—'}",
        "pin_tag": data.get("pin_tag") or _pin_tag(),
    }
    return rows, info


class RulesView(PermissionRequiredMixin, View):
    """The modulator's rules (GET /rules) as a readable table, for users
    without access to the modulator itself."""
    permission_required = USE_PERM

    def get(self, request):
        ok, data, error = client.rules(plugin_config())
        rows, info = rules_context(data or {}) if ok else ([], None)
        return render(request, "netbox_snmp_modulator/rules.html", {
            "rows": rows, "info": info, "error": None if ok else error,
        })


# ── Device card ──────────────────────────────────────────────────────────────

def _section(s, drop):
    """One modules section (normal or fast) of /rules/match, ready to render."""
    s = s or {}
    current = list(s.get("current") or [])
    add, try_ = list(s.get("add") or []), list(s.get("try") or [])
    return {
        "field": s.get("field"),
        "current": current,
        "m": {"add": add, "try": try_, "block": list(s.get("block") or [])},
        "would_remove": [m for m in current if m not in add and m not in try_] if drop else [],
        "polling": f"{s.get('interval') or '—'} / {s.get('timeout') or '—'}" if s.get("interval") or s.get("timeout") else "",
        "current_polling": (f"{s.get('current_interval') or '—'} / {s.get('current_timeout') or '—'}"
                            if s.get("current_interval") or s.get("current_timeout") else ""),
    }


def match_context(data):
    data = data or {}
    drop = data.get("module_policy") == "drop"
    fast = data.get("fast") or {}
    auth = data.get("auth") or {}
    hooks = []
    for when, h in (data.get("handlers") or {}).items():
        h = h or {}
        label = when.replace("_", " ")
        hooks += [f"{label}: +{t}" for t in h.get("add_tags") or []]
        hooks += [f"{label}: −{t}" for t in h.get("remove_tags") or []]
        hooks += [f"{label}: notify {n}" for n in h.get("notify") or []]
    return {
        "pinned": bool(data.get("pinned")),
        "pin_tag": data.get("pin_tag"),
        "module_policy": data.get("module_policy"),
        "rules": [{"index": r.get("index"), "name": r.get("name"),
                   "match": [(_rule_match_label(m.get("field") or ""), m.get("value")) for m in r.get("match") or []]}
                  for r in data.get("matched_rules") or []],
        "normal": _section(data.get("modules"), drop),
        "fast": _section(fast, drop) if fast.get("field") else None,
        "auth": {"field": auth.get("field"), "current": auth.get("current"), "rule": auth.get("rule"),
                 "use": auth.get("use"), "try": list(auth.get("try") or []), "policy": auth.get("policy")},
        "hooks": hooks,
        "version": data.get("version"),
    }


def device_card_enabled(device):
    return bool(device.role) and device.role.slug in (plugin_config().get("device_panel_roles") or ())


class DeviceCardDataView(PermissionRequiredMixin, View):
    """htmx: the body of the device card, from /rules/match."""
    permission_required = USE_PERM

    def get(self, request, pk):
        device = get_object_or_404(Device.objects.restrict(request.user, "view"), pk=pk)
        ok, data, error = client.match(plugin_config(), device.pk)
        context = {"device": device, "error": None if ok else error,
                   "unsupported": bool((data or {}).get("unsupported")) if not ok else False,
                   "not_found": bool((data or {}).get("not_found")) if not ok else False,
                   "last_updated": device.cf.get(plugin_config().get("last_updated_cf")),
                   "r": match_context(data) if ok else None}
        return render(request, "netbox_snmp_modulator/device_card_data.html", context)


def _module_diff(previous, final):
    """Merge a before/after module list into one sorted list tagged with
    each module's status, so the template can render a single list with
    additions/removals highlighted instead of two separate before/after lists."""
    previous = set(previous or [])
    final = set(final or [])
    return [
        {
            "name": m,
            "status": "added" if m in final and m not in previous else
                      "removed" if m in previous and m not in final else "unchanged",
        }
        for m in sorted(previous | final)
    ]


def _module_rows(result):
    """test_results only covers modules that were actually SNMP-probed — a module
    added unconditionally (mandatory per rule config) never gets tested, so it
    would otherwise vanish from the table despite being part of the final set.
    Returns test_results (tagged tested=True) plus a synthetic, untested row for
    each such module. Trusts a "profile" field set by the modulator itself when
    present; falls back to inferring it from module-set membership for
    modulator versions that don't set it yet."""
    final_fast = set(result.get("final_modules_fast") or [])
    previous_fast = set(result.get("previous_modules_fast") or [])

    def _profile(module_name, given):
        return given or ("fast" if module_name in final_fast or module_name in previous_fast else "normal")

    tested = [
        dict(t, tested=True, profile=_profile(t.get("module"), t.get("profile")))
        for t in (result.get("test_results") or [])
    ]
    tested_names = {t["module"] for t in tested}
    final_all = set(result.get("final_modules") or []) | final_fast
    mandatory = [
        {
            "module": m, "useful": None, "metric_count": None, "duration_seconds": None, "error": None,
            "tested": False, "profile": _profile(m, None),
        }
        for m in sorted(final_all - tested_names)
    ]
    return tested + mandatory


def _annotate_probe_result(result):
    """Add template-friendly derived flags to a ModulationResult dict in place:
    has_fast (whether the fast polling profile applies to this device at all),
    fast_changed (its module set differs from before), the merged module diffs,
    module_rows (test_results plus untested-but-mandatory modules), and pending
    (whether there's anything at all for a follow-up commit to write). Prefers
    fast_profile_enabled/changed_fast straight from the API when the modulator
    sets them, falling back to inference for older modulator versions."""
    has_fast = result.get("fast_profile_enabled")
    if has_fast is None:
        has_fast = bool(
            result.get("previous_modules_fast") or result.get("final_modules_fast") or result.get("resolved_interval_fast")
        )
    fast_changed = result.get("changed_fast")
    if fast_changed is None:
        fast_changed = result.get("previous_modules_fast") != result.get("final_modules_fast")

    result["has_fast"] = has_fast
    result["fast_changed"] = fast_changed
    result["normal_module_diff"] = _module_diff(result.get("previous_modules"), result.get("final_modules"))
    result["fast_module_diff"] = _module_diff(result.get("previous_modules_fast"), result.get("final_modules_fast"))
    result["module_rows"] = _module_rows(result)
    result["pending"] = any([
        result.get("changed"),
        result.get("auth_changed"),
        result.get("polling_interval"),
        result.get("polling_timeout"),
        result.get("polling_interval_fast"),
        result.get("polling_timeout_fast"),
        result.get("pending_add_tags"),
        result.get("pending_remove_tags"),
        fast_changed,
    ])


class ProbeView(PermissionRequiredMixin, View):
    """htmx: the Preview modal (dry run of one device, waits for the result)."""
    permission_required = RUN_PERM

    def post(self, request, pk):
        device = get_object_or_404(Device.objects.restrict(request.user, "view"), pk=pk)
        ip = _device_ip(device)
        dry_run = request.POST.get("dry_run", "true") != "false"
        wait = request.POST.get("wait", "true") != "false"
        context = {"device": device, "dry_run": dry_run, "wait": wait}
        if not ip:
            context["error"] = _("This device has no primary IPv4 address.")
        else:
            ok, status_code, data, error = client.probe(plugin_config(), ip, dry_run=dry_run, wait=wait)
            if ok and status_code == 200 and isinstance(data, dict) and isinstance(data.get("result"), dict):
                _annotate_probe_result(data["result"])
            context.update({"ok": ok, "status_code": status_code, "data": data, "error": error})
        return render(request, "netbox_snmp_modulator/probe_modal.html", context)


class ApplyView(PermissionRequiredMixin, View):
    """Apply now: queue a real probe (dry_run=false, wait=false) and go back."""
    permission_required = RUN_PERM

    def post(self, request, pk):
        device = get_object_or_404(Device.objects.restrict(request.user, "view"), pk=pk)
        ip = _device_ip(device)
        if not ip:
            messages.error(request, _("This device has no primary IPv4 address."))
            return redirect(device.get_absolute_url())
        ok, status_code, data, error = client.probe(plugin_config(), ip, dry_run=False, wait=False)
        data = data or {}
        if not ok:
            messages.error(request, error or _("SNMP Modulator request failed."))
        elif status_code == 202 and data.get("status") == "queued":
            messages.success(request, _("Module update queued for %(ip)s.") % {"ip": ip})
        elif status_code == 202:
            messages.warning(request, _("Module update skipped for %(ip)s: %(r)s.") % {
                "ip": ip, "r": data.get("reason", "already in progress")})
        else:
            messages.error(request, _("Unexpected response from SNMP Modulator (HTTP %(c)s).") % {"c": status_code})
        return redirect(device.get_absolute_url())


# ── Bulk ─────────────────────────────────────────────────────────────────────

def _bulk_filter(request):
    """The device filter from the query string, as NetBox's device list sends it."""
    params = request.GET.copy()
    for key in list(params):
        if key in _NON_FILTER_PARAMS or not any(params.getlist(key)):
            del params[key]
    return params


def _existing_roles(slugs):
    from dcim.models import DeviceRole
    found = set(DeviceRole.objects.filter(slug__in=slugs).values_list("slug", flat=True))
    return [s for s in slugs if s in found]


def _device_filters_exist(*keys):
    filters = DeviceFilterSet(None).filters
    return all(k in filters for k in keys)


def _presets(current_qs):
    """Preset filters as [{label, qs, active}], built per request so "older
    than 30 days" is always from today."""
    def qs(*pairs):
        q = QueryDict(mutable=True)
        for k, v in pairs:
            q.appendlist(k, v)
        return q.urlencode()

    cfg = plugin_config()
    base = (("has_primary_ip", "true"), ("status", "active"))
    skip = tuple(("role__n", r) for r in _existing_roles(cfg.get("bulk_exclude_roles") or []))
    stale = (timezone.localdate() - timedelta(days=STALE_DAYS)).isoformat()
    last = f"cf_{cfg.get('last_updated_cf')}"
    module_empty = f"cf_{cfg.get('module_cf')}__empty"
    has_last = _device_filters_exist(f"{last}__empty", f"{last}__lt")
    presets = [
        (_("Switches"), qs(*base, ("role", "switch"))) if _existing_roles(["switch"]) else None,
        (_("No SNMP module"), qs(*base, *skip, (module_empty, "true"))) if _device_filters_exist(module_empty) else None,
        (_("Not modulated for %(days)d days") % {"days": STALE_DAYS},
         qs(*base, *skip, (f"{last}__empty", "false"), (f"{last}__lt", stale))) if has_last else None,
        (_("Never modulated"), qs(*base, *skip, (f"{last}__empty", "true"))) if has_last else None,
    ]
    return [{"label": label, "qs": q, "active": q == current_qs} for label, q in filter(None, presets)]


def _bulk_devices(request, params):
    """(queryset, error) for a NetBox device filter, limited to what the user
    may view. limit=N (ours, not a NetBox filter) keeps the first N by name."""
    params = params.copy()
    sel = params.pop("sel", None)
    limit = params.pop("limit", None)
    limit = limit[-1] if limit else None
    if limit is not None and not (limit.isdigit() and int(limit) > 0):
        return None, f"limit: a positive number, not {limit!r}"
    fs = DeviceFilterSet(params, queryset=Device.objects.restrict(request.user, "view"))
    # a filterset ignores unknown keys, which would widen the filter to the whole fleet
    unknown = sorted(k for k in params if k not in fs.filters)
    if unknown:
        return None, f"Unknown device filter: {', '.join(unknown)}"
    if not fs.is_valid():
        return None, "; ".join(f"{k}: {', '.join(v)}" for k, v in fs.errors.items())
    qs = fs.qs
    if sel:
        ids = cache.get(f"{_SEL_KEY}:{sel[-1]}")
        if ids is None:
            return None, _("This selection has expired: tick the devices again.")
        qs = qs.filter(pk__in=ids)
    if limit:
        qs = qs.filter(pk__in=list(qs.order_by("name").values_list("pk", flat=True)[:int(limit)]))
    return qs, None


_SEL_KEY = "netbox_snmp_modulator:sel"


class BulkSelectView(PermissionRequiredMixin, View):
    """POST of many ticked device ids (too long for a URL): kept for a day
    under a short key, then the bulk page with sel=<key>."""
    permission_required = RUN_PERM

    def post(self, request):
        ids = sorted({int(i) for i in request.POST.getlist("id") if i.isdigit()})
        key = uuid.uuid4().hex[:12]
        cache.set(f"{_SEL_KEY}:{key}", ids, timeout=86400)
        return redirect(f"{reverse('plugins:netbox_snmp_modulator:bulk')}?sel={key}")


def _run_context():
    """The modulator's current or last /probe/run, ready for the template."""
    ok, run, error = client.probe_run_status(plugin_config())
    if not ok:
        return {"run_error": error, "run_unsupported": bool((run or {}).get("unsupported"))}
    run = run or {}
    if run.get("status") in (None, "none"):
        return {"run": None}
    devices = run.get("devices") or []
    urls = {d.pk: d.get_absolute_url()
            for d in Device.objects.filter(pk__in=[e.get("device_id") for e in devices if e.get("device_id")])}
    for e in devices:
        e["url"] = urls.get(e.get("device_id"))
        e["selectable"] = bool(e.get("device_id")) and e.get("status") == "ok" and bool(e.get("changed"))
        e["preselect"] = e["selectable"]
        old, new = e.get("previous_modules") or [], e.get("final_modules") or []
        e["added"] = [m for m in new if m not in old]
        e["removed"] = [m for m in old if m not in new]
    total = run.get("total") or len(devices)
    done = run.get("done") or 0
    left = (run.get("remaining") or 0) + (run.get("running") or 0)
    per = run.get("avg_duration_s") or EST_SECONDS
    return {"run": {
        **run, "devices": devices, "total": total, "done": done,
        "percent": int(done * 100 / total) if total else 0,
        "eta_min": max(1, round(left * per / 60)) if left else 0,
        "running": run.get("status") == "running",
        "selectable": any(e["selectable"] for e in devices),
    }}


_SENT_KEY = "netbox_snmp_modulator:bulk_sent"
_UNKNOWN_REASON = "not taken by the modulator"


def full_run_context():
    """The run plus the devices we sent that the modulator dropped without
    listing them, shown as "unknown" so they leave the next batch."""
    ctx = _run_context()
    sent = cache.get(_SENT_KEY)
    if not sent or ctx.get("run_error") or sent.get("over_limit"):
        return ctx
    run = ctx.get("run")
    if sent.get("status") == "running":
        started = parse_datetime((run or {}).get("started") or "")
        if not run or not started or started < sent["at"] - timedelta(minutes=2):
            return ctx
    elif sent.get("status") != "none":
        return ctx
    elif run and (parse_datetime(run.get("started") or "") or sent["at"]) > sent["at"]:
        return ctx
    listed = {e.get("device_id") for e in (run or {}).get("devices") or []}
    missing = [i for i in sent["ids"] if i not in listed]
    if not missing:
        return ctx
    names = dict(Device.objects.filter(pk__in=missing).values_list("pk", "name"))
    unknown = [{"device_id": i, "hostname": names.get(i, f"#{i}"), "status": "unknown", "selectable": False,
                "url": f"/dcim/devices/{i}/", "reason": _UNKNOWN_REASON} for i in missing]
    if run:
        run["devices"] = list(run.get("devices") or []) + unknown
    else:
        ctx["run"] = {"status": "done", "dry_run": sent.get("dry_run"), "started": sent["at"].isoformat(),
                      "devices": unknown, "total": len(unknown), "done": len(unknown), "running": False,
                      "selectable": False}
    return ctx


def _eligible(qs):
    """Devices the modulator can probe: those with an SNMP auth profile."""
    key = f"custom_field_data__{plugin_config().get('auth_cf')}"
    # a missing key, JSON null (set when the CF was added) or ""
    return qs.exclude(**{f"{key}__isnull": True}).exclude(**{key: None}).exclude(**{key: ""})


class BulkView(PermissionRequiredMixin, View):
    """Bulk: the modulator's async /probe/run over the devices of a NetBox
    device filter, batch by batch: a dry run first, then apply the devices
    ticked in its result; admins can apply a batch directly. An older
    modulator without /probe/run falls back to the fire-and-forget
    /probe/netbox. One run at a time across all users."""
    permission_required = RUN_PERM

    def get(self, request):
        params = _bulk_filter(request)
        if not params:
            params = QueryDict(mutable=True)
            params["has_primary_ip"] = "true"
            params["status"] = "active"
            params["role"] = "switch"
            return redirect(f"{request.path}?{params.urlencode()}")
        return render(request, "netbox_snmp_modulator/bulk.html", self._context(request, params))

    def _context(self, request, params):
        cfg = plugin_config()
        context = {"filter_params": params, "filter_qs": params.urlencode(),
                   "can_direct": request.user.is_superuser, "presets": _presets(params.urlencode()),
                   "page_url": request.path, "run_url": request.path + "run/"}
        context.update(full_run_context())
        devices, error = _bulk_devices(request, params)
        if error:
            context["error"] = error
            return context
        context["no_ip_count"] = devices.filter(primary_ip4__isnull=True).count()
        with_ip = devices.filter(primary_ip4__isnull=False).select_related("primary_ip4", "role", "site").order_by("name")
        run = context.get("run") or {}
        # devices the last run handled (not the cancelled ones) wait for a later batch
        handled = {e.get("device_id") for e in run.get("devices") or [] if e.get("status") != "cancelled"}
        batch_size = run.get("max_devices") or 20
        tag = _pin_tag()
        unpinned = with_ip.exclude(tags__slug=tag) if tag else with_ip
        total = with_ip.count()
        eligible = _eligible(unpinned)
        context["ineligible_count"] = unpinned.count() - eligible.count()
        pending = eligible.exclude(pk__in=handled)
        pending_count = pending.count()
        batch = list(pending[:batch_size])
        batch_ids = {d.pk for d in batch}
        listed = list(with_ip) if total <= LIST_MAX else batch
        listed_ids = [d.pk for d in listed]
        pinned = _pinned_ids(listed_ids)
        ineligible_ids = set(listed_ids) - set(_eligible(with_ip.filter(pk__in=listed_ids)).values_list("pk", flat=True))
        context.update({
            "matched": total, "list_capped": total > LIST_MAX, "list_max": LIST_MAX,
            "pin_tag": tag, "pinned_count": total - unpinned.count(), "ineligible_label": _("no SNMP auth profile"),
            "sendable": eligible.count() if total > LIST_MAX else
            len(set(eligible.filter(pk__in=listed_ids).values_list("pk", flat=True))),
            "rows": [{
                "id": d.pk, "name": d.name, "url": d.get_absolute_url(), "ip": _device_ip(d),
                "role": d.role.name if d.role else None, "site": d.site.name if d.site else None,
                "in_batch": d.pk in batch_ids, "handled": d.pk in handled, "pinned": d.pk in pinned,
                "ineligible": d.pk in ineligible_ids,
                "last": d.cf.get(cfg.get("last_updated_cf")), "module": d.cf.get(cfg.get("module_cf")),
                "auth": d.cf.get(cfg.get("auth_cf")),
            } for d in listed],
            "batch_ids": ",".join(str(d.pk) for d in batch), "batch_count": len(batch),
            "pending_count": pending_count, "batch_size": batch_size,
            "batch_eta_min": max(1, round(len(batch) * EST_SECONDS / 60)) if batch else 0,
        })
        return context

    def post(self, request):
        filter_qs = request.POST.get("filter_qs", "")
        back = redirect(f"{request.path}?{filter_qs}")
        config = plugin_config()
        action = request.POST.get("action")
        if action == "cancel":
            ok, _data, error = client.probe_run_cancel(config)
            if ok:
                messages.info(request, _("Run cancelled: the queued devices are dropped, the one running finishes."))
            else:
                messages.error(request, error)
            return back
        if action == "legacy":
            return self._legacy(request, filter_qs)
        if action == "preview":
            ids, dry_run = [i for i in request.POST.get("batch", "").split(",") if i.isdigit()], True
        elif action == "apply_batch" and request.user.is_superuser:
            ids, dry_run = [i for i in request.POST.get("batch", "").split(",") if i.isdigit()], False
        elif action == "apply_selected":
            ids, dry_run = [i for i in request.POST.getlist("device") if i.isdigit()], False
        else:
            messages.error(request, _("Unknown action."))
            return back
        if not dry_run and request.POST.get("confirm") != "yes":
            messages.error(request, _("Tick the confirmation first."))
            return back
        # only devices this user may see and that are not pinned, whatever the form sent
        ids = list(Device.objects.restrict(request.user, "view").filter(pk__in=ids).values_list("pk", flat=True))
        ids = [i for i in ids if i not in _pinned_ids(ids)]
        ids = list(_eligible(Device.objects.filter(pk__in=ids)).values_list("pk", flat=True))
        if not ids:
            messages.error(request, _("No devices selected."))
            return back
        ok, data, error = client.probe_run_start(config, ids, dry_run=dry_run)
        if not ok:
            messages.error(request, error)
            return back
        data = data or {}
        cache.set(_SENT_KEY, {"ids": ids, "at": timezone.now(), "dry_run": dry_run,
                              "status": data.get("status"), "over_limit": data.get("over_limit") or 0},
                  timeout=7 * 86400)
        msg = (_("Dry run started for %(n)d devices.") if dry_run else _("Run started for %(n)d devices.")) % {"n": data.get("queued") or 0}
        extra = [f"{data[k]} {label}" for k, label in (
            ("over_limit", _("over the limit (next batch)")), ("pinned", _("pinned")),
            ("skipped", _("skipped")), ("invalid", _("invalid"))) if data.get(k)]
        messages.success(request, msg + (" " + ", ".join(extra) + "." if extra else ""))
        return back

    def _legacy(self, request, filter_qs):
        """Older modulator: one fire-and-forget probe over the ids, in the server's mode."""
        if request.POST.get("confirm") != "yes":
            messages.error(request, _("Tick the confirmation first."))
            return redirect(f"{request.path}?{filter_qs}")
        context = self._context(request, QueryDict(filter_qs))
        ids = [r["id"] for r in context.get("rows") or [] if not r["pinned"] and not r["ineligible"]]
        if not ids:
            messages.error(request, context.get("error") or _("No devices to probe."))
        else:
            ok, data, error = client.probe_devices(plugin_config(), ids)
            if not ok:
                messages.error(request, error)
            elif (data or {}).get("status") == "queued":
                messages.success(request, _("Probe queued for %(n)d devices. Results show up in the device's SNMP fields as each one finishes.") % {"n": len(ids)})
            else:
                messages.warning(request, _("Not queued: %(r)s") % {"r": (data or {}).get("reason") or (data or {}).get("status")})
        return redirect(f"{request.path}?{filter_qs}")


class BulkRunPanelView(PermissionRequiredMixin, View):
    """htmx: the run panel of the bulk page, polled while the run is going."""
    permission_required = RUN_PERM

    def get(self, request):
        context = {"filter_qs": request.GET.get("filter_qs", ""), "run_url": request.path,
                   "page_url": request.path.removesuffix("run/")}
        context.update(full_run_context())
        response = render(request, "netbox_snmp_modulator/bulk_run.html", context)
        if not (context.get("run") or {}).get("running"):
            # the run just ended: reload the page so the batch and the device list catch up
            response["HX-Refresh"] = "true"
        return response
