"use client";

import { AlertTriangleIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import {
  asList,
  asRecord,
  NOTABLE_USN,
  pick,
  siFnComparison,
  TIME_FIELD_LABEL,
  timestompIndicators,
  usnReasons,
  viewerKind,
} from "@/lib/artifacts";
import { formatNs, stringifyValue } from "@/lib/format";
import type { AttrValue, TimelineEvent } from "@/lib/types";
import { cn } from "@/lib/utils";

type Attrs = Record<string, AttrValue>;

function KV({ rows, label }: { rows: [string, ReactNode][]; label: string }) {
  const shown = rows.filter(([, v]) =>
    typeof v === "string" ? v.replace(/[\s:/—]/g, "") !== "" : v !== undefined && v !== null,
  );
  if (!shown.length) return null;
  return (
    <table className="w-full text-sm" aria-label={label}>
      <tbody>
        {shown.map(([k, v]) => (
          <tr key={k} className="border-b last:border-0">
            <th
              scope="row"
              className="text-muted-foreground w-40 py-1 pr-2 text-left align-top text-xs font-medium"
            >
              {k}
            </th>
            <td className="py-1 break-all">{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const s = (v: AttrValue | undefined): string => (v === undefined ? "" : stringifyValue(v));
const t = (v: AttrValue | undefined): string => (typeof v === "number" ? formatNs(v) : s(v));

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="grid gap-2" aria-label={title}>
      <h3 className="text-muted-foreground text-xs font-semibold uppercase">{title}</h3>
      {children}
    </section>
  );
}

function ListBlock({ items, label }: { items: AttrValue[]; label: string }) {
  if (!items.length) return null;
  return (
    <Section title={`${label} (${items.length})`}>
      <ol className="bg-muted/40 max-h-56 overflow-auto rounded-md border p-2 font-mono text-xs">
        {items.map((it, i) => (
          <li key={i} className="break-all">
            {s(it)}
          </li>
        ))}
      </ol>
    </Section>
  );
}

export function EvtxViewer({ attrs }: { attrs: Attrs }) {
  const data = asRecord(attrs.event_data) ?? {};
  const xml = pick(attrs, "xml_string", "xml");
  return (
    <div className="grid gap-3">
      <KV
        label="Event record"
        rows={[
          ["Event ID", s(pick(attrs, "event_identifier", "event_id"))],
          ["Channel", s(pick(attrs, "channel"))],
          ["Provider", s(pick(attrs, "source_name", "provider"))],
          ["Computer", s(pick(attrs, "computer_name", "computer"))],
          ["Record number", s(pick(attrs, "record_number"))],
          ["Level", s(pick(attrs, "level"))],
          ["User SID", s(pick(attrs, "user_sid"))],
        ]}
      />
      {Object.keys(data).length ? (
        <Section title="Event data">
          <KV label="Event data" rows={Object.entries(data).map(([k, v]) => [k, s(v)])} />
        </Section>
      ) : null}
      {typeof xml === "string" && xml ? (
        <Section title="XML">
          <pre className="bg-muted/40 max-h-72 overflow-auto rounded-md border p-2 text-xs whitespace-pre-wrap">
            {xml}
          </pre>
        </Section>
      ) : null}
    </div>
  );
}

export function PrefetchViewer({ attrs }: { attrs: Attrs }) {
  const runs = asList(pick(attrs, "run_times", "last_run_times", "last_run_time"));
  return (
    <div className="grid gap-3">
      <KV
        label="Prefetch"
        rows={[
          ["Executable", s(pick(attrs, "executable", "executable_name"))],
          ["Run count", s(pick(attrs, "run_count"))],
          ["Prefetch hash", s(pick(attrs, "prefetch_hash", "hash"))],
          ["Format version", s(pick(attrs, "format_version", "version"))],
          ["Volume", s(pick(attrs, "volume_device_path", "volume_serial"))],
        ]}
      />
      {runs.length ? (
        <Section title={`Run times (${runs.length})`}>
          <ol className="grid gap-0.5 font-mono text-xs">
            {runs.map((r, i) => (
              <li key={i}>{t(r)}</li>
            ))}
          </ol>
        </Section>
      ) : null}
      <ListBlock
        items={asList(pick(attrs, "mapped_files", "loaded_files", "filenames"))}
        label="Loaded files"
      />
    </div>
  );
}

export function RegistryViewer({ attrs }: { attrs: Attrs }) {
  const values = asRecord(attrs.values);
  return (
    <div className="grid gap-3">
      <KV
        label="Registry key"
        rows={[
          ["Key path", s(pick(attrs, "key_path", "key"))],
          ["Value name", s(pick(attrs, "value_name", "name"))],
          ["Value type", s(pick(attrs, "value_type", "type"))],
          ["Value data", s(pick(attrs, "value_data", "data", "value"))],
          ["Hive", s(pick(attrs, "hive", "hive_path"))],
          ["Key last written", t(pick(attrs, "last_written_ns", "last_written"))],
          ["Path", s(pick(attrs, "path", "full_path", "binary_path"))],
        ]}
      />
      {values ? (
        <Section title="Values">
          <KV
            label="Registry values"
            rows={Object.entries(values).map(([k, v]) => [k || "(default)", s(v)])}
          />
        </Section>
      ) : null}
    </div>
  );
}

export function LnkViewer({ attrs }: { attrs: Attrs }) {
  return (
    <KV
      label="Shortcut or jump list entry"
      rows={[
        ["Target path", s(pick(attrs, "local_path", "link_target", "path"))],
        ["Arguments", s(pick(attrs, "command_line_arguments", "arguments"))],
        ["Working directory", s(pick(attrs, "working_directory"))],
        ["Volume label", s(pick(attrs, "volume_label"))],
        ["Drive serial", s(pick(attrs, "drive_serial_number", "volume_serial"))],
        ["Machine ID", s(pick(attrs, "machine_identifier", "machine_id"))],
        ["Droid volume", s(pick(attrs, "droid_volume_identifier"))],
        ["Target size", s(pick(attrs, "file_size", "target_size"))],
        ["Target created", t(pick(attrs, "target_creation_time_ns", "creation_time"))],
        ["Target modified", t(pick(attrs, "target_modification_time_ns", "modification_time"))],
        ["App ID", s(pick(attrs, "app_id", "appid"))],
        ["Entry number", s(pick(attrs, "entry_number"))],
      ]}
    />
  );
}

export function BrowserViewer({ attrs, dataType }: { attrs: Attrs; dataType: string }) {
  const download = /download/.test(dataType);
  return (
    <KV
      label={download ? "Browser download" : "Browser history entry"}
      rows={[
        ["URL", s(pick(attrs, "url", "source_url"))],
        ["Title", s(pick(attrs, "title"))],
        ["Saved to", s(pick(attrs, "full_path", "target_path", "path"))],
        ["Referrer", s(pick(attrs, "referrer", "referrer_url"))],
        ["Received bytes", s(pick(attrs, "received_bytes"))],
        ["Total bytes", s(pick(attrs, "total_bytes"))],
        ["State", s(pick(attrs, "state", "danger_type"))],
        ["MIME type", s(pick(attrs, "mime_type"))],
        ["Visit count", s(pick(attrs, "visit_count"))],
        ["Typed count", s(pick(attrs, "typed_count"))],
        ["Transition", s(pick(attrs, "page_transition_type", "transition"))],
        ["Profile", s(pick(attrs, "profile"))],
      ]}
    />
  );
}

export function FsViewer({ attrs }: { attrs: Attrs }) {
  const rows = siFnComparison(attrs);
  const indicators = timestompIndicators(attrs);
  return (
    <div className="grid gap-3">
      <KV
        label="File system entry"
        rows={[
          ["Path", s(pick(attrs, "path", "name", "filename"))],
          ["MFT entry", s(pick(attrs, "mft_entry", "inode", "file_reference"))],
          ["Sequence", s(pick(attrs, "sequence", "sequence_number"))],
          ["Size", s(pick(attrs, "size", "file_size"))],
          ["Allocated", s(pick(attrs, "is_allocated", "allocated"))],
          ["Attribute", s(pick(attrs, "attribute_name"))],
        ]}
      />
      {indicators.length ? (
        <div
          role="note"
          className="border-destructive text-destructive flex items-start gap-2 rounded-md border p-2 text-sm"
          data-testid="timestomp"
        >
          <AlertTriangleIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
          <div>
            <p className="font-medium">Possible timestomping</p>
            <ul className="list-disc pl-4 text-xs">
              {indicators.map((i) => (
                <li key={i}>{i}</li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}
      {rows.length ? (
        <Section title="$STANDARD_INFORMATION vs $FILE_NAME">
          <table className="w-full text-xs" aria-label="SI and FN timestamps">
            <thead>
              <tr className="text-muted-foreground border-b">
                <th scope="col" className="py-1 text-left font-medium">
                  Time
                </th>
                <th scope="col" className="py-1 text-left font-medium">
                  $SI
                </th>
                <th scope="col" className="py-1 text-left font-medium">
                  $FN
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr
                  key={r.field}
                  className={cn(
                    "border-b last:border-0",
                    r.flags.length && "bg-destructive/10 text-destructive",
                  )}
                >
                  <th scope="row" className="py-1 pr-2 text-left font-medium">
                    {TIME_FIELD_LABEL[r.field]}
                    {r.flags.length ? (
                      <span className="sr-only"> (inconsistent: {r.flags.join("; ")})</span>
                    ) : null}
                  </th>
                  <td className="py-1 pr-2 font-mono">{formatNs(r.si)}</td>
                  <td className="py-1 font-mono">{formatNs(r.fn)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      ) : null}
    </div>
  );
}

export function UsnViewer({ attrs }: { attrs: Attrs }) {
  const reasons = usnReasons(attrs);
  return (
    <div className="grid gap-3">
      <KV
        label="USN change record"
        rows={[
          ["Path", s(pick(attrs, "path", "filename"))],
          ["USN", s(pick(attrs, "usn", "update_sequence_number"))],
          ["File reference", s(pick(attrs, "file_reference", "mft_entry"))],
          ["Parent reference", s(pick(attrs, "parent_file_reference", "parent_mft_entry"))],
          ["Source info", s(pick(attrs, "update_source_flags", "source_info"))],
          ["File attributes", s(pick(attrs, "file_attribute_flags", "file_attributes"))],
        ]}
      />
      {reasons.length ? (
        <Section title="Reasons">
          <ul className="flex flex-wrap gap-1">
            {reasons.map((r) => (
              <li key={r}>
                <Badge
                  variant={NOTABLE_USN.has(r) ? (r === "FILE_DELETE" ? "destructive" : "warning") : "outline"}
                >
                  {r}
                </Badge>
              </li>
            ))}
          </ul>
        </Section>
      ) : null}
    </div>
  );
}

export function MemoryViewer({ attrs, dataType }: { attrs: Attrs; dataType: string }) {
  const kind = viewerKind(dataType);
  if (kind === "memory-network") {
    return (
      <KV
        label="Network connection"
        rows={[
          ["Protocol", s(pick(attrs, "Proto", "proto"))],
          ["Local", `${s(pick(attrs, "LocalAddr"))}:${s(pick(attrs, "LocalPort"))}`],
          ["Remote", `${s(pick(attrs, "ForeignAddr"))}:${s(pick(attrs, "ForeignPort"))}`],
          ["State", s(pick(attrs, "State"))],
          ["PID", s(pick(attrs, "PID", "pid"))],
          ["Owner", s(pick(attrs, "Owner"))],
          ["Plugin", s(pick(attrs, "plugin"))],
        ]}
      />
    );
  }
  if (kind === "memory-injection") {
    const dump = pick(attrs, "Hexdump", "Disasm");
    return (
      <div className="grid gap-3">
        <KV
          label="Injected memory region"
          rows={[
            ["Process", s(pick(attrs, "Process", "ImageFileName"))],
            ["PID", s(pick(attrs, "PID", "pid"))],
            ["Start VPN", s(pick(attrs, "Start VPN"))],
            ["End VPN", s(pick(attrs, "End VPN"))],
            ["Protection", s(pick(attrs, "Protection"))],
            ["Tag", s(pick(attrs, "Tag"))],
            ["Notes", s(pick(attrs, "Notes"))],
            ["Plugin", s(pick(attrs, "plugin"))],
          ]}
        />
        {typeof dump === "string" ? (
          <Section title="Region dump">
            <pre className="bg-muted/40 max-h-64 overflow-auto rounded-md border p-2 text-xs">{dump}</pre>
          </Section>
        ) : null}
      </div>
    );
  }
  return (
    <KV
      label="Process"
      rows={[
        ["Image", s(pick(attrs, "ImageFileName", "Name", "COMM"))],
        ["PID", s(pick(attrs, "PID", "pid"))],
        ["PPID", s(pick(attrs, "PPID", "ppid"))],
        ["Threads", s(pick(attrs, "Threads"))],
        ["Handles", s(pick(attrs, "Handles"))],
        ["Session", s(pick(attrs, "SessionId"))],
        ["Wow64", s(pick(attrs, "Wow64"))],
        ["Created", s(pick(attrs, "CreateTime"))],
        ["Exited", s(pick(attrs, "ExitTime"))],
        ["Command line", s(pick(attrs, "Args", "ARGS"))],
        ["Plugin", s(pick(attrs, "plugin"))],
      ]}
    />
  );
}

export function NetworkViewer({ attrs, dataType }: { attrs: Attrs; dataType: string }) {
  return (
    <KV
      label="Network record"
      rows={[
        ["Record", dataType],
        ["UID", s(pick(attrs, "uid"))],
        [
          "Source",
          `${s(pick(attrs, "id.orig_h", "src_ip", "orig_h"))}:${s(pick(attrs, "id.orig_p", "src_port", "orig_p"))}`,
        ],
        [
          "Destination",
          `${s(pick(attrs, "id.resp_h", "dst_ip", "resp_h"))}:${s(pick(attrs, "id.resp_p", "dst_port", "resp_p"))}`,
        ],
        ["Protocol", s(pick(attrs, "proto", "protocol", "service"))],
        ["Duration", s(pick(attrs, "duration"))],
        ["Bytes out/in", `${s(pick(attrs, "orig_bytes"))} / ${s(pick(attrs, "resp_bytes"))}`],
        ["Query", s(pick(attrs, "query"))],
        ["Answers", s(pick(attrs, "answers"))],
        ["Method", s(pick(attrs, "method"))],
        ["Host", s(pick(attrs, "host", "server_name", "sni"))],
        ["URI", s(pick(attrs, "uri"))],
        ["Status", s(pick(attrs, "status_code"))],
        ["User agent", s(pick(attrs, "user_agent"))],
        ["TLS version", s(pick(attrs, "version"))],
        ["JA3", s(pick(attrs, "ja3"))],
        ["JA3S", s(pick(attrs, "ja3s"))],
        ["Certificate subject", s(pick(attrs, "subject", "certificate.subject"))],
        ["Issuer", s(pick(attrs, "issuer", "certificate.issuer"))],
      ]}
    />
  );
}

export function CloudViewer({ attrs }: { attrs: Attrs }) {
  return (
    <KV
      label="Cloud audit entry"
      rows={[
        [
          "Operation",
          s(pick(attrs, "event_name", "eventName", "operation", "Operation", "operationName", "activity")),
        ],
        ["Service", s(pick(attrs, "event_source", "eventSource", "service", "Workload", "category"))],
        [
          "Actor",
          s(pick(attrs, "user_identity", "userIdentity", "user_principal_name", "UserId", "caller", "actor")),
        ],
        [
          "Source IP",
          s(pick(attrs, "source_ip", "sourceIPAddress", "ClientIP", "ip_address", "callerIpAddress")),
        ],
        ["User agent", s(pick(attrs, "user_agent", "userAgent"))],
        ["Result", s(pick(attrs, "result", "ResultStatus", "error_code", "errorCode", "status"))],
        ["Region / tenant", s(pick(attrs, "aws_region", "awsRegion", "tenant_id", "OrganizationId"))],
        ["Resource", s(pick(attrs, "resource", "resourceId", "ObjectId", "target"))],
        ["Request ID", s(pick(attrs, "request_id", "requestID", "correlationId", "Id"))],
      ]}
    />
  );
}

/** Specialized renderer for an event's artifact type; null when only the generic table applies. */
export function ArtifactViewer({ event }: { event: TimelineEvent }) {
  const kind = viewerKind(event.data_type);
  const a = event.attrs;
  switch (kind) {
    case "evtx":
      return <EvtxViewer attrs={a} />;
    case "prefetch":
      return <PrefetchViewer attrs={a} />;
    case "registry":
      return <RegistryViewer attrs={a} />;
    case "lnk":
      return <LnkViewer attrs={a} />;
    case "browser":
      return <BrowserViewer attrs={a} dataType={event.data_type} />;
    case "fs":
      return <FsViewer attrs={a} />;
    case "usn":
      return <UsnViewer attrs={a} />;
    case "memory-process":
    case "memory-network":
    case "memory-injection":
    case "memory":
      return <MemoryViewer attrs={a} dataType={event.data_type} />;
    case "network":
      return <NetworkViewer attrs={a} dataType={event.data_type} />;
    case "cloud":
      return <CloudViewer attrs={a} />;
    case "generic":
      return null;
  }
}
