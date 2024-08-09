namespace NodeJS {
  interface ProcessEnv {
    PORT?: string;
    JWT_SECRET: string;
    JWT_REFRESH_SECRET: string;
   
    GMAIL_SENDER_EMAIL : string
    GMAIL_SENDER_PASSWORD : string
    COOKIE_SECRET : string
    
    FRONTEND_URL : string
    SERVER_URL : string
    DATABASE_URL : string

    GOOGLE_CLIENT_SECRET : string
    GOOGLE_CLIENT_ID : string
    GOOGLE_CALLBACK_URL : string
  }
}