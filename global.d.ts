declare namespace NodeJS {
  interface ProcessEnv {
    PORT?: string;
    JWT_SECRET: string;
    JWT_REFRESH_SECRET: string;
  }
}