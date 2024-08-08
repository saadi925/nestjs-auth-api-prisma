import {
  Controller,
  Post,
  Body,
  Req,
  Res,
  HttpCode,
  HttpStatus,
  UseGuards,
  Put,
  Get,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-auth.dto';
import { Request, Response } from 'express';
import {
  RefreshTokenGuard,
  RequestWithRefreshUser,
} from './tokens/refresh-token.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() createUserDto: CreateUserDto, @Res() res: Response) {
    try {
      const result = await this.authService.register(createUserDto);
      return res.status(HttpStatus.CREATED).json(result);
    } catch (error) {
      return res
        .status(HttpStatus.BAD_REQUEST)
        .json({ message: error.message });
    }
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: { email: string; password: string },
    @Res() res: Response,
  ) {
    const { email, password } = loginDto;

    try {
      const { accessToken, refreshToken } = await this.authService.login(
        email,
        password,
      );
      this.setCookies(res, accessToken, refreshToken);
      return res
        .status(HttpStatus.OK)
        .json({ message: 'Logged in successfully' });
    } catch (error) {
      return res
        .status(HttpStatus.UNAUTHORIZED)
        .json({ message: error.message });
    }
  }
  @Post('refresh')
  @UseGuards(RefreshTokenGuard)
  async refresh(@Req() req: RequestWithRefreshUser, @Res() res: Response) {
    const { user } = req;
    const newAccessToken = await this.authService.refreshAccessToken(user.sub);
    this.setCookies(
      res,
      newAccessToken.accessToken,
      newAccessToken.refreshToken,
    );
  }

  private setCookies(res: Response, accessToken: string, refreshToken: string) {
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
      maxAge: 3600 * 1000, // 1 hour
      sameSite: 'strict',
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
      maxAge: 7 * 24 * 3600 * 1000, // 7 days
      sameSite: 'strict', // or 'Lax' based on your needs
    });
  }

  @Put('verify-email')
  async verifyEmail(
    @Body() { token }: { token: string },
    @Res() res: Response,
  ) {
    try {
      await this.authService.verifyEmail(token);
      return res.status(HttpStatus.OK).json({ message: 'Email verified' });
    } catch (error) {
      return res
        .status(HttpStatus.BAD_REQUEST)
        .json({ message: error.message });
    }
  }

  @Get('logout')
  async logout(@Res() res: Response) {
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    return res.status(HttpStatus.OK).json({ message: 'Logged out successfully' });
  }
}
