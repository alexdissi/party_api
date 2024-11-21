import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { compare, hash } from 'bcrypt';
import { MailerService } from 'src/mailer.service';
import { PrismaService } from 'src/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';
import { ResetUserPasswordDto } from './dto/reset-user-password.dto';
import { UserPayload } from './jwt.strategy';
import { LoginUserDto } from './dto/login-user.dto';
import { randomBytes } from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly mailerService: MailerService,
  ) {}

  async login({ authBody }: { authBody: LoginUserDto }) {
    const { email, password } = authBody;

    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!existingUser) {
      throw new HttpException("User does not exist.", HttpStatus.NOT_FOUND);
    }

    const isPasswordValid = await this.isPasswordValid({
      password,
      hashedPassword: existingUser.password,
    });

    if (!isPasswordValid) {
      throw new HttpException('Invalid password.', HttpStatus.UNAUTHORIZED);
    }

    return this.authenticateUser({ userId: existingUser.id });
  }

  async register({ registerBody }: { registerBody: CreateUserDto }) {
    const { email, firstName, lastName, password, passwordConfirm, age } = registerBody;
    const name = `${firstName} ${lastName}`;
    const profilePictureUrl: string = `https://api.dicebear.com/7.x/initials/svg?seed=${name}`;

    if (password !== passwordConfirm) {
      throw new HttpException('Passwords do not match.', HttpStatus.BAD_REQUEST);
    }

    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new HttpException('User already exists.', HttpStatus.BAD_REQUEST);
    }

    const hashedPassword = await this.hashPassword({ password });

    const createdUser = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
        profilePictureUrl,
        createdAt: new Date(),
        age: parseInt(age),
      },
    });

    await this.mailerService.sendCreatedAccountEmail({
      firstName: name,
      recipient: email,
    });

    return this.authenticateUser({ userId: createdUser.id });
  }

  private async hashPassword({ password }: { password: string }) {
    return await hash(password, 10);
  }

  private async isPasswordValid({
    password,
    hashedPassword,
  }: {
    password: string;
    hashedPassword: string;
  }) {
    return await compare(password, hashedPassword);
  }

  private authenticateUser({ userId }: UserPayload) {
    const payload: UserPayload = { userId };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async resetUserPasswordRequest({ email }: { email: string }) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!existingUser) {
      throw new HttpException("User does not exist.", HttpStatus.NOT_FOUND);
    }

    if (existingUser.isResettingPassword) {
      throw new HttpException(
        "A password reset request is already in progress.",
        HttpStatus.BAD_REQUEST,
      );
    }

    const createdId = randomBytes(32).toString('hex');
    await this.prisma.user.update({
      where: { email },
      data: {
        isResettingPassword: true,
        resetPasswordToken: createdId,
      },
    });

    await this.mailerService.sendRequestedPasswordEmail({
      firstName: existingUser.name,
      recipient: existingUser.email,
      token: createdId,
    });

    return {
      error: false,
      message: 'Please check your email to reset your password.',
    };
  }

  async verifyResetPasswordToken({ token }: { token: string }) {
    const existingUser = await this.prisma.user.findUnique({
      where: { resetPasswordToken: token },
    });

    if (!existingUser) {
      throw new HttpException({
        status: HttpStatus.NOT_FOUND,
        error: 'The reset token is incorrect.',
      }, HttpStatus.NOT_FOUND);
    }

    if (!existingUser.isResettingPassword) {
      throw new HttpException({
        status: HttpStatus.BAD_REQUEST,
        error: "No password reset request is in progress.",
      }, HttpStatus.BAD_REQUEST);
    }

    return {
      status: HttpStatus.OK,
      message: 'The reset token is valid.',
    };
  }

  async resetUserPassword({
    resetPasswordDto,
  }: {
    resetPasswordDto: ResetUserPasswordDto;
  }) {
    const { password, token } = resetPasswordDto;

    const existingUser = await this.prisma.user.findUnique({
      where: { resetPasswordToken: token },
    });

    if (!existingUser) {
      throw new HttpException("User does not exist.", HttpStatus.NOT_FOUND);
    }

    if (!existingUser.isResettingPassword) {
      throw new HttpException(
        "No password reset request is in progress.",
        HttpStatus.BAD_REQUEST,
      );
    }

    const hashedPassword = await this.hashPassword({ password });
    await this.prisma.user.update({
      where: { resetPasswordToken: token },
      data: {
        isResettingPassword: false,
        password: hashedPassword,
        dateResetPassword: new Date(),
      },
    });

    return {
      error: false,
      message: 'Your password has been successfully changed.',
    };
  }
}
