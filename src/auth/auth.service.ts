import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from 'src/prisma-nest/prisma.service';
import { CreateUserDto } from './dto/create-auth.dto';
import { TokenService } from './tokens/token.service';
import { EmailService } from './email/email.service';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private readonly tokenService: TokenService,
    private readonly emailService: EmailService,
  ) {}

  async register(createUserDto: CreateUserDto) {
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    //   check that user does not exist
    const existingUser = await this.prisma.user.findUnique({
      where: {
        email: createUserDto.email,
      },
    });
    if (existingUser) {
      throw new UnauthorizedException('User already exists');
    }
    if (!existingUser.emailVerified) {
      //  send email verification
      await this.sendVerificationEmail(existingUser.email);
      return {
        message: `Email verification sent to ${existingUser.email}`,
      };
    }

    await this.prisma.user.create({
      data: {
        email: createUserDto.email,
        password: hashedPassword,
        name: createUserDto.name,
      },
    });
    // send email verification
    await this.sendVerificationEmail(createUserDto.email);
    return {
      message: `Email verification sent to ${createUserDto.email}`,
    };
  }

  async login(email: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException();
    }
    if (!user.emailVerified) {
      // send email verification
      // TODO : send email verification email
      return {
        message: `Email verification sent to ${user.email}`,
      };
    }
    const accessToken = this.tokenService.generateToken(user);
    const refreshToken = await this.tokenService.generateRefreshToken(user.id);
    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshAccessToken(sub: string): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    const tokens = await this.tokenService.refreshAccessToken(sub);
    return tokens;
  }

  async verifyEmail(token: string) {
    const payload = await this.tokenService.getVerificationTokenByToken(token);
    if (!payload) {
      throw new UnauthorizedException('Invalid token');
    }
    // payload.expires
    if (payload.expires < new Date()) {
      throw new UnauthorizedException('Token expired');
    }

    const user = await this.prisma.user.findUnique({
      where: { email: payload.email },
    });
    if (!user) {
      throw new UnauthorizedException('Invalid token');
    }
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerified: new Date(),
        email: payload.email,
      },
    });
  }

  private async sendVerificationEmail(email: string) {
    const token = await this.tokenService.createVerificationToken(
    email);

    const link = `${process.env.SERVER_URL}/auth/verify-email?token=${token}`;
    await this.emailService.sendVerificationEmail(email, link);  
  }
}
