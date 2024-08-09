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
  Delete,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, CredentialsDto, ForgotPasswordDto, ResetPasswordDto } from './dto/create-auth.dto';
import { Response, Request } from 'express';
import {
  RefreshTokenGuard,
  RequestWithRefreshUser,
} from './tokens/refresh-token.guard';
import { JwtAuthGuard } from './guards/jwt.guard';
export interface IUser {
  email: string;
  role: "USER" | "ADMIN";
  status?: string;
  name : string
  picture?: string;
  emailVerified?: Date | null;
}
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
  async login(
    @Body() body: CredentialsDto,
    @Res() res: Response,
  ) {
    const { email, password } = body    
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
  @HttpCode(HttpStatus.OK)
  async refresh(@Req() req: RequestWithRefreshUser, @Res() res: Response) {
   try {
    const { user } = req;
    
    const newAccessToken = await this.authService.refreshAccessToken(user);
    this.setCookies(
      res,
      newAccessToken.accessToken,
      newAccessToken.refreshToken,
    );
    return res
    .status(HttpStatus.OK)
    .json({ message: 'Refreshed Successfully' });
   } catch (error) {
    return res
    .status(HttpStatus.UNAUTHORIZED)
    .json({ message: error.message });
   }
  }
  @Get("logout")
  @UseGuards(RefreshTokenGuard)
  @HttpCode(HttpStatus.OK)
  async revokeAllTokens(@Req() req: RequestWithRefreshUser, @Res() res: Response) {
    try {
  
      await this.authService.logout(req.user)
      res.clearCookie('access_token');
      res.clearCookie('refresh_token');
      return res
      .status(HttpStatus.OK)
      .json({ message: "Logged out Successfully" }); 
    } catch (error) {
      return res
      .status(HttpStatus.UNAUTHORIZED)
      .json({ message: error.message }); 
    }
  }



  private setCookies(res: Response, accessToken: string, refreshToken: string) {
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
      maxAge: 3600 * 1000, // 1 hour
      // signed : true,
      sameSite: "lax",
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
      maxAge: 7 * 24 * 3600 * 1000, // 7 days
      // signed : true,
      sameSite: "lax", // or 'Lax' based on your needs
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


  @Post('forgot-password')
   async forgotPassword(@Body() { email }: ForgotPasswordDto, @Res() res: Response) {
  try {

    await this.authService.forgotPassword(email);
    return res.status(HttpStatus.OK).json({ message: 'Password reset email sent' });
  } catch (error) {
    return res
      .status(HttpStatus.BAD_REQUEST)
      .json({ message: error.message });
  }}

  @Put('reset-password')
  async resetPassword(
    @Body() { token, password }: ResetPasswordDto,
    @Res() res: Response,
  ) {
    try {
      await this.authService.resetPassword(token, password);
      return res.status(HttpStatus.OK).json({ message: 'Password changed successfully' });
    } catch (error) {
      return res
        .status(HttpStatus.BAD_REQUEST)
        .json({ message: error.message });
    }
  }

  @Get("session")
  @UseGuards(JwtAuthGuard)
  async getSession(@Req() req : Request, @Res() res : Response){
     try {
      
const user =  await this.authService.getCurrentUser(req.cookies["access_token"]);
return res.status(200).json({ user})
     } catch (error) {
      return res.status(403).json({user : null})
     }
  }


}
