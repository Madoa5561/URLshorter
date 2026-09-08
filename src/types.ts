export interface Bindings {
  DB: D1Database;
  ASSETS?: Fetcher;
  ADMIN_SECRET?: string;
  BASE_URL?: string;
}

export interface UrlMappingRow {
  shortened: string;
  original: string;
  og_title: string | null;
  og_description: string | null;
  og_image: string | null;
  created_at: string;
  access_count: number;
  access_limit: number | null;
  expires_at: string | null;
}

export interface AccessLogRow {
  id?: number;
  type: string;
  message: string;
  details: string | null;
  timestamp?: string;
}

export interface OgMeta {
  title: string | null;
  description: string | null;
  image: string | null;
}
