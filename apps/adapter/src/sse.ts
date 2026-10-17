export interface SseEvent {
  event?: string;
  id?: string;
  data: string;
}

/** Incremental Server-Sent Events parser that accepts arbitrary transport chunk boundaries. */
export class SseParser {
  private buffer = "";
  private data: string[] = [];
  private eventDataChars = 0;
  private hasData = false;
  private eventName: string | undefined;
  private eventId: string | undefined;

  constructor(private readonly maxBufferedChars = 1024 * 1024) {}

  push(chunk: string): SseEvent[] {
    this.buffer += chunk;
    if (this.buffer.length > this.maxBufferedChars) {
      throw new Error("SSE event exceeded the configured buffer limit");
    }
    return this.consumeLines(false);
  }

  finish(): SseEvent[] {
    const events = this.consumeLines(true);
    this.dispatch(events);
    return events;
  }

  private consumeLines(final: boolean): SseEvent[] {
    const events: SseEvent[] = [];
    let start = 0;
    while (start < this.buffer.length) {
      let end = start;
      while (end < this.buffer.length && this.buffer[end] !== "\n" && this.buffer[end] !== "\r") end += 1;
      if (end === this.buffer.length) break;
      if (this.buffer[end] === "\r" && end + 1 === this.buffer.length && !final) break;
      const line = this.buffer.slice(start, end);
      const delimiter = this.buffer[end] === "\r" && this.buffer[end + 1] === "\n" ? 2 : 1;
      this.processLine(line, events);
      start = end + delimiter;
    }
    this.buffer = this.buffer.slice(start);
    if (final && this.buffer.length > 0) {
      this.processLine(this.buffer, events);
      this.buffer = "";
    }
    if (final) this.dispatch(events);
    return events;
  }

  private processLine(line: string, events: SseEvent[]): void {
    if (line === "") {
      this.dispatch(events);
      return;
    }
    if (line.startsWith(":")) return;

    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    const value = colon === -1 ? "" : line.slice(colon + 1).replace(/^ /, "");
    switch (field) {
      case "data":
        this.eventDataChars += value.length + 1;
        if (this.eventDataChars > this.maxBufferedChars) {
          throw new Error("SSE event exceeded the configured buffer limit");
        }
        this.data.push(value);
        this.hasData = true;
        break;
      case "event":
        this.eventName = value;
        break;
      case "id":
        if (!value.includes("\u0000")) this.eventId = value;
        break;
      default:
        break;
    }
  }

  private dispatch(events: SseEvent[]): void {
    if (!this.hasData) {
      this.eventName = undefined;
      return;
    }
    events.push({
      ...(this.eventName === undefined ? {} : { event: this.eventName }),
      ...(this.eventId === undefined ? {} : { id: this.eventId }),
      data: this.data.join("\n"),
    });
    this.data = [];
    this.eventDataChars = 0;
    this.hasData = false;
    this.eventName = undefined;
  }
}
