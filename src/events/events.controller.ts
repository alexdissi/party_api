import { 
  Controller, 
  Get, 
  Post, 
  Body, 
  Patch, 
  Param, 
  Delete, 
  UseGuards, 
  Query, 
  HttpException, 
  HttpStatus, 
  Req
} from '@nestjs/common';
import { EventsService } from './events.service';
import { CreateEventDto } from './dto/create-event.dto';
import { UpdateEventDto } from './dto/update-event.dto';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { PaginationDTO } from './dto/pagination.dto';

@Controller('events')
@UseGuards(JwtAuthGuard)
export class EventsController {
  constructor(private readonly eventsService: EventsService) {}

  @Post()
  async createEvent(@Body() createEventDto: CreateEventDto) {
    try {
      await this.eventsService.create(createEventDto);
      return { message: 'Event created successfully' };
    } catch (error) {
      throw new HttpException(
        { message: 'Error creating event', error: error.message },
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Get('search')
  async searchEvents(
    @Query('message') message: string,
    @Query() pagination: PaginationDTO,
  ) {
    const { page, limit } = pagination;
    try {
      return await this.eventsService.search(message, Number(page), Number(limit));
    } catch (error) {
      throw new HttpException(
        { message: 'Error searching events', error: error.message },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get()
  async getAllEvents(@Query() pagination: PaginationDTO) {
    const { page, limit } = pagination;
    try {
      return await this.eventsService.getAll(page, limit);
    } catch (error) {
      throw new HttpException(
        { message: 'Error fetching events', error: error.message },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get(':id')
  async getEventById(@Param('id') id: string) {
    try {
      const event = await this.eventsService.findById(id);
      if (!event) {
        throw new HttpException('Event not found', HttpStatus.NOT_FOUND);
      }
      return event;
    } catch (error) {
      throw new HttpException(
        { message: 'Error fetching event by ID', error: error.message },
        HttpStatus.NOT_FOUND,
      );
    }
  }

  @Patch(':id')
  async updateEvent(
    @Param('id') id: string,
    @Body() updateEventDto: UpdateEventDto,
    @Req() req: any,
  ) {
    try {
      const userId = req.user.userId;
      return this.eventsService.updateEvent(id, updateEventDto, userId);
    } catch (error) {
      throw new HttpException(
        { message: 'Error updating event', error: error.message },
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Delete(':id')
  async deleteEvent(@Param('id') id: string,
    @Req() req: any,
) {
    try {
      const userId = req.user.userId;
      await this.eventsService.delete(id, userId);
      return { message: 'Event deleted successfully' };
    } catch (error) {
      throw new HttpException(
        { message: 'Error deleting event', error: error.message },
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Get('organizer/:organizerId')
  async getEventsByOrganizer(
    @Param('organizerId') organizerId: string,
    @Query() pagination: PaginationDTO,
  ) {
    const { page, limit } = pagination;
    try {
      return await this.eventsService.findByOrganizer(organizerId, page, limit);
    } catch (error) {
      throw new HttpException(
        { message: 'Error fetching events by organizer', error: error.message },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('city/:cityId')
  async getEventsByCity(
    @Param('cityId') cityId: string,
    @Query() pagination: PaginationDTO,
  ) {
    const { page, limit } = pagination;
    try {
      return await this.eventsService.findByCity(cityId, page, limit);
    } catch (error) {
      throw new HttpException(
        { message: 'Error fetching events by city', error: error.message },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('type/:typeId')
  async getEventsByType(
    @Param('typeId') typeId: string,
    @Query() pagination: PaginationDTO,
  ) {
    const { page, limit } = pagination;
    try {
      return await this.eventsService.findByType(typeId, page, limit);
    } catch (error) {
      throw new HttpException(
        { message: 'Error fetching events by type', error: error.message },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
