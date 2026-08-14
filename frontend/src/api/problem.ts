export type ProblemLike = {
  type?: string;
  title?: string;
  status?: number;
  errors?: { path?: string; code?: string; message?: string }[];
};

export class ApiError extends Error {
  readonly status: number;
  readonly problem: ProblemLike | undefined;

  constructor(status: number, problem: ProblemLike | undefined, fallback: string) {
    const title = problem?.title?.trim();
    super(title && title.length > 0 ? title : fallback);
    this.name = "ApiError";
    this.status = status;
    this.problem = problem;
  }

  get unauthorized(): boolean {
    return this.status === 401;
  }

  get forbidden(): boolean {
    return this.status === 403;
  }

  get rateLimited(): boolean {
    return this.status === 429 || hasFieldCode(this.problem, "rate_limited");
  }

  get directoryUnavailable(): boolean {
    return this.status === 502 || this.status === 503 || this.status === 504;
  }

  get revisionConflict(): boolean {
    if (this.status === 412) {
      return true;
    }
    return (
      this.problem?.errors?.some(
        (field) => field.code === "conflict" && (field.path === "revision" || field.path === "If-Match"),
      ) === true
    );
  }

  get cycle(): boolean {
    return this.problem?.errors?.some((field) => field.code === "cycle") === true;
  }

  fieldErrors(): { path: string; code?: string; message: string }[] {
    const fields = this.problem?.errors;
    if (fields === undefined) {
      return [];
    }
    const out: { path: string; code?: string; message: string }[] = [];
    for (const field of fields) {
      if (field.path === undefined || field.message === undefined) {
        continue;
      }
      const item: { path: string; code?: string; message: string } = {
        path: field.path,
        message: field.message,
      };
      if (field.code !== undefined) {
        item.code = field.code;
      }
      out.push(item);
    }
    return out;
  }

  requiredScope(): string | undefined {
    const fields = this.problem?.errors;
    if (fields === undefined) {
      return undefined;
    }
    for (const field of fields) {
      if (field.path === "scope" && field.message) {
        return field.message;
      }
    }
    return undefined;
  }
}

export function isApiError(err: unknown): err is ApiError {
  return err instanceof ApiError;
}

export function isUnauthorized(err: unknown): boolean {
  return isApiError(err) && err.unauthorized;
}

export function toApiError(error: unknown, status: number, fallback = "request failed"): ApiError {
  return new ApiError(status, asProblem(error), fallback);
}

export function asProblem(error: unknown): ProblemLike | undefined {
  if (error === null || typeof error !== "object") {
    return undefined;
  }
  const rec = error as Record<string, unknown>;
  const problem: ProblemLike = {};
  if (typeof rec.type === "string") {
    problem.type = rec.type;
  }
  if (typeof rec.title === "string") {
    problem.title = rec.title;
  }
  if (typeof rec.status === "number") {
    problem.status = rec.status;
  }
  const errors = asFields(rec.errors);
  if (errors !== undefined) {
    problem.errors = errors;
  }
  return problem;
}

function asFields(value: unknown): ProblemLike["errors"] {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const out: NonNullable<ProblemLike["errors"]> = [];
  for (const item of value) {
    if (item === null || typeof item !== "object") {
      continue;
    }
    const rec = item as Record<string, unknown>;
    const field: NonNullable<ProblemLike["errors"]>[number] = {};
    if (typeof rec.path === "string") {
      field.path = rec.path;
    }
    if (typeof rec.code === "string") {
      field.code = rec.code;
    }
    if (typeof rec.message === "string") {
      field.message = rec.message;
    }
    out.push(field);
  }
  return out;
}

function hasFieldCode(problem: ProblemLike | undefined, code: string): boolean {
  return problem?.errors?.some((field) => field.code === code) === true;
}
