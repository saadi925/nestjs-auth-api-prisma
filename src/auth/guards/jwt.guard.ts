import { Injectable, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard as PassportAuthGuard } from '@nestjs/passport';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

@Injectable()
export class JwtAuthGuard extends PassportAuthGuard('jwt') {
  constructor(private jwtService: JwtService) {
    super();
  }
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const token = request.cookies?.['access_token'] || request.headers.authorization?.split(' ')[1];

    if (!token) {
      throw new UnauthorizedException('unauthorized');
    }
    try {
       

      const payload = await this.jwtService.verify(token, {
        secret: process.env.JWT_SECRET
      });
      request.user = payload; // Attach user payload to the request object
      return true;
    } catch (error) {
      console.log(error);
      
      throw new UnauthorizedException('Invalid token');
    }
  }
}
