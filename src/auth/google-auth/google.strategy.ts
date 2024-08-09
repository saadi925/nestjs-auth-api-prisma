import { Strategy } from 'passport-google-oauth20';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma-nest/prisma.service';
import { VerifyCallback } from 'passport-google-oauth20';
import { AccountType } from '@prisma/client';
import { TokenService } from '../tokens/token.service';
interface GoogleAuthProfile {
  id: string;
  displayName: string;
  name: { familyName: string; givenName: string };
  emails: [{ value: string; verified: boolean }];
  photos: { value: string }[];
  provider: string
  _json: {
    sub: string;
    name: string;
    picture: string;
    email: string;
    emailVerified: boolean;
  };
}
@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tokenService: TokenService,
  ) {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      scope: ['profile', 'email'],
    });
  }

  authorizationParams(): { [key: string]: string } {
    return {
      access_type: 'offline',
      prompt: 'consent',
    };
  }

  async validate(
    accessToken: string,
    refreshToken: string | undefined,
    profile: GoogleAuthProfile,
    done: VerifyCallback,
  ): Promise<void> {
    const { id, emails, name, photos, provider } = profile;
    const email = emails[0].value;
    const emailVerified = emails[0].verified ? new Date() : undefined;
    try {
      // Check if the account already exists
      let account = await this.prisma.account.findUnique({
        where: {
          provider_providerAccountId: {
            provider,
            providerAccountId: id,
          },
        },
        include: {
          user: true, // Ensure user information is included
        },
      });

      if (account) {
        // If account exists, return the existing user and your own tokens
        const user = account.user;
        const accessToken = this.tokenService.generateToken(user);
        const refreshToken = await this.tokenService.generateRefreshToken(
          user.id,
        );

        return done(null, {
          user,
          accessToken,
          refreshToken,
        });
      }
      // if there is no account
      // Create or update the user in the database
      const user = await this.prisma.user.upsert({
        where: { email },
        update: {
          name: `${name.givenName} ${name.familyName}`,
          image: photos[0].value,
          emailVerified, // Assuming the email is verified by Google
        },
        create: {
          email,
          name: `${name.givenName} ${name.familyName}`,
          image: photos[0].value,
          emailVerified,
        },
      });

      // Create the account in the database
      account = await this.prisma.account.create({
        data: {
          userId: user.id,
          type: AccountType.OAUTH,
          provider: 'google',
          providerAccountId: id,
          refreshToken: refreshToken ?? '', // Handle undefined refreshToken
          accessToken,
          expiresAt: new Date(Date.now() + 3600 * 1000), // Access token expiration
        },
        include: {
          user: true, // Include user information
        },
      });

      // Generate your own tokens
      const newAccessToken = this.tokenService.generateToken(user);
      const newRefreshToken = await this.tokenService.generateRefreshToken(
        user.id,
      );

      done(null, {
        user: account.user,
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      });
    } catch (error) {
      done(error, false);
    }
  }
}
