import { IsString, IsBoolean, IsInt, IsOptional, IsDateString, IsDecimal } from 'class-validator';


export class CreateEventDto {
    @IsString()
    organizerId: string;
  
    @IsString()
    eventTypeId: string;
  
    @IsString()
    cityId: string;
  
    @IsString()
    name: string;
  
    @IsString()
    address: string;
  
    @IsDateString()
    dateTime: string;
  
    @IsInt()
    maxParticipants: number;
  
    @IsBoolean()
    isPaid: boolean;
  
    @IsOptional()
    @IsDecimal({ decimal_digits: '2' })
    price?: number;
  
    @IsString()
    description: string;
}
