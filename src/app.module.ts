import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { GoogleAuthModule } from './auth/google-auth/google-auth.module';
import { PrismaModule } from './prisma-nest/prisma.module';

@Module({
  imports: [AuthModule, GoogleAuthModule, PrismaModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
