import { Controller, Get, Param, Req, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { AuthGuard } from '@nestjs/passport';

@Controller('users')
export class UserController {
    constructor(private readonly userService: UserService) {}
    @Get()
    getUsers() {
        return this.userService.getUsers();
    }
    @UseGuards(AuthGuard('jwt'))
    @Get('/info')
    async getUser(@Req() req: any) {
      if (!req.user || !req.user.userId) {
        throw new Error("L'utilisateur n'est pas authentifié.");
      }

      const userId = req.user.userId;
      return this.userService.getUser({ userId });
    }
}
