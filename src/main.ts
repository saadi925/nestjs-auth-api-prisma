import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import * as cookieParser from 'cookie-parser';
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser(process.env.COOKIE_SECRET));
 app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
  }));
  app.enableCors({
    origin : "http://localhost:4000",  credentials : true
  })
  await app.listen(process.env?.PORT || 3000);
}
bootstrap();
