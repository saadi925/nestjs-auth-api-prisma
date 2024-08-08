import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Response, Request } from 'express';

@Controller('auth/google')
export class GoogleAuthController {
  @Get('login')
  @UseGuards(AuthGuard('google'))
  async googleLogin(@Req() req: Request) {
    // The @UseGuards(AuthGuard('google')) will trigger the Google OAuth flow.
  }

  @Get('callback')
  @UseGuards(AuthGuard('google'))
  async googleCallback(@Req() req: Request, @Res() res: Response) {
    // Successful authentication, redirect to your frontend or any desired location
    const { user, accessToken, refreshToken } = req.user as any;
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Ensure cookies are secure in production
      sameSite: 'strict',
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
  }

   
}
