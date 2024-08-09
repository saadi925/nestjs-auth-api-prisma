import { Controller, Get, Req, Res, UseGuards, HttpStatus } from '@nestjs/common';
import { Response, Request } from 'express';
import { GoogleAuthGuard } from './google-auth.guard';

@Controller('/api/auth')
export class GoogleAuthController {

  @Get('google')
  @UseGuards(GoogleAuthGuard)
  async googleLogin() {
    // Trigger the Google OAuth flow
  }

  @Get('callback/google')
  @UseGuards(GoogleAuthGuard)
  async googleCallback(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    try {
      const { user, accessToken, refreshToken } = req.user as any;

      // Check if user and tokens exist
      if (!user || !accessToken || !refreshToken) {
        res.status(HttpStatus.UNAUTHORIZED).json({ message: 'Authentication failed' });
        return;
      }
      // Set cookies
      const isProduction = process.env.NODE_ENV === 'production';
      res.cookie('access_token', accessToken, {
        httpOnly: true,
        secure: isProduction,
        maxAge: 3600 * 1000, // 1 hour
        sameSite: 'lax',
      });
      res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: isProduction,
        maxAge: 7 * 24 * 3600 * 1000, // 7 days
        sameSite: 'lax',
      });
      // Redirect to frontend
      return res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
    } catch (error) {
      // Handle errors (e.g., log the error, send error response)
     return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ message: 'An error occurred during authentication' });
    }
  }

  
}
