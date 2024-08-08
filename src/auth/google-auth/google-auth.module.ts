import { Module } from '@nestjs/common';
import { GoogleAuthController } from './google-auth.controller';
import { GoogleStrategy } from './google.strategy';
import { PrismaService } from 'src/prisma-nest/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { TokenService } from '../tokens/token.service';

@Module({
  controllers: [GoogleAuthController],
  providers: [GoogleStrategy, TokenService, PrismaService, JwtService],
})
export class GoogleAuthModule {}
