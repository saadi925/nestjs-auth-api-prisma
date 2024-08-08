import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User, UserRole } from '@prisma/client';
import axios from 'axios';
import { PrismaService } from 'src/prisma-nest/prisma.service';
import * as uuidV4 from 'uuid';
export interface JwtPayload {
  sub: string;
  email: string;
  role: UserRole;
  emailVerified?: Date | null;
  status?: string;
  picture?: string;
  iat?: number; // Issued at time, automatically handled by JWT library
  exp?: number; // Expiration time, automatically handled by JWT library
}

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  generateToken(user: User): string {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      picture: user.image,
      emailVerified: user.emailVerified,
      status: user.status,
    };

    return this.jwtService.sign(payload, { secret: process.env.JWT_SECRET });
  }
  async generateRefreshToken(userId: string): Promise<string> {
    const payload = { sub: userId };
    const refreshToken = this.jwtService.sign(payload, {
      secret: process.env.JWT_REFRESH_SECRET,
      expiresIn: '7d', // Refresh token valid for 7 days
    });

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // Refresh token valid for 7 days

    await this.prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId,
        expiresAt,
      },
    });
    

    return refreshToken;
  }

  async refreshAccessToken(refreshToken: string): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    const storedToken = await this.prisma.refreshToken.findUnique({
      where: { token: refreshToken },
      include: { user: true },
    });

    if (!storedToken || new Date() > storedToken.expiresAt) {
      throw new UnauthorizedException('Invalid or expired refresh token.');
    }

    // Generate new JWT
    const newAccessToken = this.generateToken(storedToken.user);

    // Rotate the refresh token (invalidate old one and issue a new one)
    await this.prisma.refreshToken.delete({ where: { id: storedToken.id } });

    const newRefreshToken = await this.generateRefreshToken(storedToken.userId);

    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  }

  async revokeRefreshToken(token: string): Promise<void> {
    await this.prisma.refreshToken.deleteMany({ where: { token } });
  }

  async revokeUserTokens(userId: string): Promise<void> {
    await this.prisma.refreshToken.deleteMany({ where: { userId } });
  }

  // google auth related methods
  async getNewAccessToken(refreshToken: string): Promise<string> {
    try {
      const response = await axios.post(
        'https://accounts.google.com/o/oauth2/token',
        {
          client_id: process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          refresh_token: refreshToken,
          grant_type: 'refresh_token',
        },
      );

      if (
        response.data &&
        typeof response.data === 'object' &&
        'access_token' in response.data &&
        typeof response.data.access_token === 'string'
      ) {
        return response.data.access_token;
      }
    } catch (error) {
      throw new Error('Failed to refresh the access token.');
    }
  }
  // google auth related methods
  async isTokenExpired(token: string): Promise<boolean> {
    try {
      const response = await axios.get(
        `https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=${token}`,
      );

      if (
        response.data &&
        typeof response.data === 'object' &&
        'expires_in' in response.data &&
        typeof response.data.expires_in === 'number'
      ) {
        const expiresIn = response.data.expires_in;

        if (!expiresIn || expiresIn <= 0) {
          return true;
        }
      }
    } catch (error) {
      return true;
    }
  }
  // google auth related methods
  async revokeGoogleToken(token: string) {
    try {
      await axios.get(
        `https://accounts.google.com/o/oauth2/revoke?token=${token}`,
      );
    } catch (error) {
      console.error('Failed to revoke the token:', error);
    }
  }


  async createVerificationToken(email: string) {
      const exists = await this.getVerificationToken(email);
      if (exists) {
        await this.prisma.verificationToken.delete({
          where: {
            id: exists.id,
          },
        });
      }
  //    creating a new token
      const token = await this.prisma.verificationToken.create({
        data: {
          email,
          token: uuidV4.v4(),
          expires: new Date(Date.now() + 1000 * 60 * 60),
        },
      });
      return token;
    
  }

  // Email verification related methods
  private async getVerificationToken(email: string) {
    return await this.prisma.verificationToken.findFirst({
      where: {
        email,
      },
    });
  }

  // Email verification related methods
  async getVerificationTokenByToken(token: string) {
    return await this.prisma.verificationToken.findUnique({
      where: {
        token,
      },
    });
  }


  // Reset password related methods
  async createResetPasswordToken(email: string) {
    const exists = await this.getResetPasswordToken(email);
    if (exists) {
      await this.prisma.resetPasswordToken.delete({
        where: {
          id: exists.id,
        },
      });
    }

    const token = await this.prisma.resetPasswordToken.create({
      data: {
        email,
        token: uuidV4.v4(),
        expires: new Date(Date.now() + 1000 * 60 * 60),
      },
    });
    return token;
  }
  async getResetPasswordToken(email: string) {
    return await this.prisma.resetPasswordToken.findFirst({
      where: {
        email,
      },
    });
  }
  async getResetPasswordTokenByToken(token: string) {
    return await this.prisma.resetPasswordToken.findUnique({
      where: {
        token,
      },
    });
  }

}
