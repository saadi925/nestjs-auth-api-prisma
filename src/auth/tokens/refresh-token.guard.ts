import { Injectable, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard as PassportAuthGuard } from '@nestjs/passport';
import { JwtService } from '@nestjs/jwt';
export interface RequestWithRefreshUser extends Request {
    user: {
        sub: string;
        refreshToken : string
    };
    }
@Injectable()
export class RefreshTokenGuard extends PassportAuthGuard('jwt-refresh') {
  constructor(private jwtService: JwtService) {
    super();
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const refreshToken = request.cookies?.['refresh_token'];

    if (!refreshToken) {
      throw new UnauthorizedException('No refresh token provided');
    }

    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });

      // console.log("refreshToken :", refreshToken);
      
      request.user = {
        ...payload, refreshToken
      }; // Attach user payload to the request object
      return true;
    } catch (error) {
      console.log(error);
      
      throw new UnauthorizedException('Invalid refresh token');
    }
  }
}
