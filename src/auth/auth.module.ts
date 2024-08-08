import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaService } from 'src/prisma-nest/prisma.service';
import { TokenService } from './tokens/token.service';
import { EmailService } from './email/email.service';
import { TemplateService } from './email/template.service';
import { JwtModule } from '@nestjs/jwt';
import { RefreshTokenGuard } from './tokens/refresh-token.guard';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '1h' },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    PrismaService,
    TokenService,
    EmailService,
    TemplateService,
    JwtStrategy,
    RefreshTokenGuard,
  ],
  exports: [AuthService],
})
export class AuthModule {}
