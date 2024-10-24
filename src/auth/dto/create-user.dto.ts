import { 
  IsEmail, 
  IsNotEmpty, 
  IsString, 
  Matches, 
  MaxLength, 
  MinLength 
} from 'class-validator';

export class CreateUserDto {
  @IsEmail({}, {
    message: 'Vous devez fournir une adresse email valide.',
  })
  @Matches(/^(?!.*\+\d+)[^\s@]+@[^\s@]+\.[^\s@]+$/, {
    message: 'L\'adresse email ne doit pas contenir de + suivi de chiffres.',
  })
  email: string;

  @IsNotEmpty({ message: 'Le mot de passe est requis.' })
  @MinLength(8, {
    message: 'Le mot de passe doit contenir au moins 8 caractères.',
  })
  @MaxLength(32, {
    message: 'Le mot de passe ne peut pas dépasser 32 caractères.',
  })
  @Matches(/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$/, {
    message: 'Le mot de passe doit inclure des majuscules, des minuscules, des chiffres et des caractères spéciaux.',
  })
  password: string;

  @IsNotEmpty({ message: 'La confirmation du mot de passe est requise.' })
  passwordConfirm: string;

  @IsNotEmpty({ message: 'Vous devez fournir un prénom.' })
  @IsString({ message: 'Le prénom doit être une chaîne de caractères.' })
  @MinLength(1, { message: 'Le prénom ne peut pas être vide.' })
  @MaxLength(32, { message: 'Le prénom ne peut pas dépasser 32 caractères.' })
  firstName: string;

  @IsNotEmpty({ message: 'Vous devez fournir un nom de famille.' })
  @IsString({ message: 'Le nom de famille doit être une chaîne de caractères.' })
  @MinLength(1, { message: 'Le nom de famille ne peut pas être vide.' })
  @MaxLength(32, { message: 'Le nom de famille ne peut pas dépasser 32 caractères.' })
  lastName: string;
}
