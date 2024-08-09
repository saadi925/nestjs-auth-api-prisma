import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { GoogleAuthModule } from './auth/google-auth/google-auth.module';
import { PrismaModule } from './prisma-nest/prisma.module';

@Module({
  imports: [AuthModule, GoogleAuthModule, PrismaModule],
})
export class AppModule {}
