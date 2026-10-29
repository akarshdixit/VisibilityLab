"use client";

import { useRef, useState } from "react";
import { uploadWithProgress } from "@/lib/api";
import { ErrorText } from "./ui";

export type UploadKind = "json" | "pe" | "zip";

interface Props {
  title: string;
  hint?: string;
  accept: UploadKind;
  maxMb: number;
  path: string;
  fields?: Record<string, string>;
  onDone: (result: unknown) => void;
}

const EXT: Record<UploadKind, string> = { json: ".json", pe: ".exe,.dll,.bin,.sample,.sys", zip: ".zip" };

async function sniff(file: File, kind: UploadKind): Promise<string | null> {
  const head = new Uint8Array(await file.slice(0, 4).arrayBuffer());
  if (kind === "pe" && !(head[0] === 0x4d && head[1] === 0x5a)) return "not a Windows PE file (no MZ header)";
  if (kind === "zip" && !(head[0] === 0x50 && head[1] === 0x4b)) return "not a .zip file";
  if (kind === "json") {
    const text = (await file.slice(0, 64).text()).replace(/^﻿/, "").trimStart();
    if (!text.startsWith("{") && !text.startsWith("[")) return "not a JSON document";
  }
  return null;
}

/** Drag-and-drop upload with client-side type/size checks. The server re-validates everything. */
export function Uploader({ title, hint, accept, maxMb, path, fields, onDone }: Props) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const [pct, setPct] = useState<number | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [ok, setOk] = useState<string | null>(null);

  async function send(file: File) {
    setError(null);
    setOk(null);
    if (file.size > maxMb * 1024 * 1024) return setError(new Error(`file is larger than the ${maxMb} MB limit`));
    if (file.size === 0) return setError(new Error("file is empty"));
    const bad = await sniff(file, accept);
    if (bad) return setError(new Error(bad));
    const form = new FormData();
    Object.entries(fields ?? {}).forEach(([k, v]) => form.append(k, v));
    form.append("file", file, file.name);
    setPct(0);
    try {
      const res = await uploadWithProgress(path, form, setPct);
      setOk(`${file.name} accepted`);
      onDone(res);
    } catch (e) {
      setError(e);
    } finally {
      setPct(null);
    }
  }

  return (
    <div>
      <div
        className={`dropzone${over ? " over" : ""}`}
        role="button"
        tabIndex={0}
        onClick={() => input.current?.click()}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          const f = e.dataTransfer.files[0];
          if (f) void send(f);
        }}
      >
        <strong style={{ color: "var(--text)" }}>{title}</strong>
        <div className="hint">{hint ?? `Drop a ${EXT[accept]} file or click to choose. Max ${maxMb} MB.`}</div>
        <input
          ref={input}
          type="file"
          accept={EXT[accept]}
          hidden
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void send(f);
            e.target.value = "";
          }}
        />
      </div>
      {pct !== null && (
        <div className="progress" style={{ marginTop: 8 }} aria-label="upload progress">
          <div style={{ width: `${pct}%` }} />
        </div>
      )}
      <ErrorText error={error} />
      {ok && <p className="okmsg">{ok}</p>}
    </div>
  );
}
