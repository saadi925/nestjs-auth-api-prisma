import { IsEmail, IsNotEmpty, IsString, Max, MaxLength } from 'class-validator';

export class CreateUserDto {
  @IsNotEmpty({
    message: 'Name is required',
  })
  @MaxLength(50)
  name: string;

  @IsEmail()
  @IsNotEmpty({
    message: 'Email is required',
  })
  email: string;
  @IsNotEmpty({
    message: 'Password is required',
  })
  @MaxLength(100)
  password: string;
}

export class CredentialsDto {
  @IsEmail()
  @IsNotEmpty({
    message: 'Email is required',
  })
  email: string;
  @IsNotEmpty({
    message: 'Password is required',
  })
  password: string;
}

export class ForgotPasswordDto {
  @IsEmail()
  @IsNotEmpty({
    message: 'Email is required',
  })
  email : string
}

export class ResetPasswordDto {
  @IsString()
  token : string

  @IsString()
  @IsNotEmpty()
  password : string
}