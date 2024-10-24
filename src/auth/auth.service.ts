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
import { ok } from 'assert';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly mailerService: MailerService,
  ) {}
  async login({ authBody }: { authBody: LoginUserDto }) {
    try {
      const { email, password } = authBody;

      const existingUser = await this.prisma.user.findUnique({
        where: {
          email,
        },
      });

      if (!existingUser) {
        throw new HttpException("L'utilisateur n'existe pas.", HttpStatus.NOT_FOUND);
      }

      const isPasswordValid = await this.isPasswordValid({
        password,
        hashedPassword: existingUser.password,
      });

      if (!isPasswordValid) {
        throw new HttpException('Le mot de passe est invalide.', HttpStatus.UNAUTHORIZED);
      }
      return this.authenticateUser({
        userId: existingUser.id,
      });
    } catch (error) {
      throw new HttpException(error.message, error.status || HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  async register({ registerBody }: { registerBody: CreateUserDto }) {
      const { email, firstName,lastName, password,passwordConfirm  } = registerBody;
      const name = firstName + ' ' + lastName;
      const profilePictureUrl: string = `https://api.dicebear.com/7.x/initials/svg?seed=${name}`;

      if (password !== passwordConfirm) {
        throw new HttpException('Les mots de passe ne correspondent pas.', HttpStatus.BAD_REQUEST);
      }

      const existingUser = await this.prisma.user.findUnique({
        where: {
          email,
        },
      });

      if (existingUser) {
        throw new HttpException('L\'utilisateur existe déjà.', HttpStatus.BAD_REQUEST);
      }

      const hashedPassword = await this.hashPassword({ password });

      const createdUser = await this.prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          name,
          profilePictureUrl,
          createdAt: new Date(),
        },
      });

      await this.mailerService.sendCreatedAccountEmail({
        firstName: name,
        recipient: email,
      });

      return this.authenticateUser({
        userId: createdUser.id,
      });
  }

  private async hashPassword({ password }: { password: string }) {
    const hashedPassword = await hash(password, 10);
    return hashedPassword;
  }
  private async isPasswordValid({
    password,
    hashedPassword,
  }: {
    password: string;
    hashedPassword: string;
  }) {
    const isPasswordValid = await compare(password, hashedPassword);
    return isPasswordValid;
  }

  private authenticateUser({ userId }: UserPayload) {
    const payload: UserPayload = { userId };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async resetUserPasswordRequest({ email }: { email: string }) {
      const existingUser = await this.prisma.user.findUnique({
        where: {
          email,
        },
      });

      if (!existingUser) {
        throw new HttpException("L'utilisateur n'existe pas.", HttpStatus.NOT_FOUND);
      }

      if (existingUser.isResettingPassword === true) {
        throw new HttpException(
          "Une demande de réinitialisation de mot de passe est déjà en cours.",
          HttpStatus.BAD_REQUEST,
        );
      }

      const createdId = randomBytes(32).toString('hex');
      await this.prisma.user.update({
        where: {
          email,
        },
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

      console.log("Email envoyée");
      

      return {
        error: false,
        message:
          'Veuillez consulter vos emails pour réinitialiser votre mot de passe.',
      };
  }

  async verifyResetPasswordToken({ token }: { token: string }) {
    // Chercher l'utilisateur avec le token de réinitialisation
    const existingUser = await this.prisma.user.findUnique({
      where: {
        resetPasswordToken: token,
      },
    });
  
    // Vérifier si l'utilisateur existe
    if (!existingUser) {
      throw new HttpException({
        status: HttpStatus.NOT_FOUND,
        error: 'Le token de réinitialisation est incorrect',
      }, HttpStatus.NOT_FOUND);
    }
  
    // Vérifier si une demande de réinitialisation est en cours
    if (existingUser.isResettingPassword === false) {
      throw new HttpException({
        status: HttpStatus.BAD_REQUEST,
        error: "Aucune demande de réinitialisation de mot de passe n'est en cours.",
      }, HttpStatus.BAD_REQUEST);
    }
  
    // Réinitialisation réussie, retourner un message de succès
    return {
      status: HttpStatus.OK,
      message: 'Le token de réinitialisation est valide.',
    };
  }
  

  async resetUserPassword({
    resetPasswordDto,
  }: {
    resetPasswordDto: ResetUserPasswordDto;
  }) {
    try {
      const { password, token } = resetPasswordDto;
      const existingUser = await this.prisma.user.findUnique({
        where: {
          resetPasswordToken: token,
        },
      });

      if (!existingUser) {
        throw new Error("L'utilisateur n'existe pas.");
      }

      if (existingUser.isResettingPassword === false) {
        throw new Error(
          "Aucune demande de réinitialisation de mot de passe n'est en cours.",
        );
      }

      const hashedPassword = await this.hashPassword({
        password,
      });
      await this.prisma.user.update({
        where: {
          resetPasswordToken: token,
        },
        data: {
          isResettingPassword: false,
          password: hashedPassword,
          dateResetPassword: new Date(),
        },
      });

      return {
        error: false,
        message: 'Votre mot de passe a bien été changé.',
      };
    } catch (error) {
      return { error: true, message: error.message };
    }
  }
}