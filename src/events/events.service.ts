import { Injectable } from '@nestjs/common';

import { CreateEventDto } from './dto/create-event.dto';
import { UpdateEventDto } from './dto/update-event.dto';
import { EventsRepository } from './events.repository';

@Injectable()
export class EventsService {
  constructor(private readonly eventsRepository: EventsRepository) {}

  async create(createEventDto: CreateEventDto) {
    return this.eventsRepository.create(createEventDto);
  }

  async getAll(page: number, limit: number) {
    return this.eventsRepository.findAll(page, limit);
  }

  async findById(id: string) {
    return this.eventsRepository.findById(id);
  }

  async update(id: string, updateEventDto: UpdateEventDto) {
    return this.eventsRepository.update(id, updateEventDto);
  }

  async delete(id: string) {
    return this.eventsRepository.delete(id);
  }

  async search(keyword: string, page: number, limit: number) {
    return this.eventsRepository.search(keyword, page, limit);
  }

  async findByOrganizer(organizerId: string, page: number, limit: number) {
    return this.eventsRepository.findByOrganizer(organizerId, page, limit);
  }

  async findByCity(cityId: string, page: number, limit: number) {
    return this.eventsRepository.findByCity(cityId, page, limit);
  }

  async findByType(typeId: string, page: number, limit: number) {
    return this.eventsRepository.findByType(typeId, page, limit);
  }
}
