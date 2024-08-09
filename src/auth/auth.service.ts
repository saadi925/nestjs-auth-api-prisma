import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from 'src/prisma-nest/prisma.service';
import { CreateUserDto } from './dto/create-auth.dto';
import { TokenService } from './tokens/token.service';
import { EmailService } from './email/email.service';
import { IUser } from './auth.controller';

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

      if (!existingUser.emailVerified) {
        //  send email verification
        await this.sendVerificationEmail(existingUser.email);
        return {
          message: `Email verification sent to ${existingUser.email}`,
        };
      }else  throw new UnauthorizedException('User already exists');
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
      throw new UnauthorizedException('Invalid credentials');
    }
    if (!user.emailVerified) {
   await this.sendVerificationEmail(user.email);
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

  async refreshAccessToken(refreshData): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    
    const tokens = await this.tokenService.refreshAccessToken(refreshData);
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
  async forgotPassword(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new UnauthorizedException('Invalid email');
    }
    const token = await this.tokenService.createResetPasswordToken(email);
    const link = `${process.env.FRONTEND_URL}/auth/reset-password?token=${token.token}`;
    await this.emailService.sendResetPasswordEmail(email, link);
  }

  async resetPassword(token: string, password: string) {
    const payload = await this.tokenService.getResetPasswordTokenByToken(token);
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
      throw new UnauthorizedException('Invalid token or session expired, try again');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
      },
    });
    await this.prisma.resetPasswordToken.delete({
      where : {
        id : payload.id,
        token : payload.token
      }
    })
  }

  private async sendVerificationEmail(email: string) {
    const token = await this.tokenService.createVerificationToken(
    email);

    const link = `${process.env.SERVER_URL}/auth/verify-email?token=${token?.token || ""}`;
    await this.emailService.sendVerificationEmail(email, link);  
  }
  async logout(refreshData : {
    sub : string
    refreshToken : string
  }){
  this.tokenService.revokeRefreshToken(refreshData.refreshToken)
  this.tokenService.revokeUserTokens(refreshData.sub)
  }


  async getCurrentUser(access_token?: string) : Promise<IUser> {
  if (!access_token) return null
    return await this.tokenService.decodeUserFromAccessToken(access_token)
  }
}
