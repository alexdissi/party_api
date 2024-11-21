import { Injectable } from '@nestjs/common';
import { CreateEventDto } from './dto/create-event.dto';
import { UpdateEventDto } from './dto/update-event.dto';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class EventsRepository {
  constructor(private readonly prisma: PrismaService) {}

  async create(createEventDto: CreateEventDto) {
    return this.prisma.event.create({
      data: createEventDto,
    });
  }

  async findAll(page: number, limit: number) {
    const skip = (page - 1) * limit;
    return this.prisma.event.findMany({
      skip,
      take: limit,
      orderBy: { createdAt: 'asc' },
      select: {
        id: true,
        name: true,
        address: true,
        dateTime: true,
        isPaid: true,
        price: true,
        description: true,
        organizer: {
          select: {
            name: true,
          },
        },
        city: {
          select: {
            name: true,
            region: true,
          },
        },
        eventType: {
          select: {
            type: true,
          },
        },
      },
    });
  }

  async findById(id: string) {
    return this.prisma.event.findUnique({
      where: { id },
      select: {
        id: true,
        name: true,
        address: true,
        dateTime: true,
        isPaid: true,
        price: true,
        description: true,
        organizer: {
          select: {
            name: true,
          },
        },
        city: {
          select: {
            name: true,
            region: true,
          },
        },
        eventType: {
          select: {
            type: true,
          },
        },
      },
    });
  }

  async update(id: string, updateEventDto: UpdateEventDto) {
    return this.prisma.event.update({
      where: { id },
      data: updateEventDto,
    });
  }

  async delete(id: string) {
    return this.prisma.event.delete({ where: { id } });
  }

  async search(keyword: string, page: number, limit: number) {
    const skip = (page - 1) * limit;
  
    return this.prisma.event.findMany({
      where: {
        OR: [
          {
            name: {
              contains: keyword,
              mode: 'insensitive',
            },
          },
          {
            organizer: {
              name: {
                contains: keyword,
                mode: 'insensitive',
              },
            },
          },
        ],
      },
      skip,
      take: limit,
      include: {
        organizer: true,
        city: true,      
        eventType: true,
      },
    });
  }  
  
  async findByOrganizer(organizerId: string, page: number, limit: number) {
    const skip = (page - 1) * limit;
    return this.prisma.event.findMany({
      where: { organizerId },
      skip,
      take: limit,
      select: {
        id: true,
        name: true,
        address: true,
        dateTime: true,
        isPaid: true,
        price: true,
        description: true,
        organizer: {
          select: {
            name: true,
          },
        },
        city: {
          select: {
            name: true,
            region: true,
          },
        },
        eventType: {
          select: {
            type: true,
          },
        },
      },
    });
  }

  async findByCity(cityId: string, page: number, limit: number) {
    const skip = (page - 1) * limit;
    return this.prisma.event.findMany({
      where: { cityId },
      skip,
      take: limit,
      select: {
        id: true,
        name: true,
        address: true,
        dateTime: true,
        isPaid: true,
        price: true,
        description: true,
        organizer: {
          select: {
            name: true,
          },
        },
        city: {
          select: {
            name: true,
            region: true,
          },
        },
        eventType: {
          select: {
            type: true,
          },
        },
      },
    });
  }

  async findByType(typeId: string, page: number, limit: number) {
    const skip = (page - 1) * limit;
    return this.prisma.event.findMany({
      where: { eventTypeId: typeId },
      skip,
      take: limit,
      select: {
        id: true,
        name: true,
        address: true,
        dateTime: true,
        isPaid: true,
        price: true,
        description: true,
        organizer: {
          select: {
            name: true,
          },
        },
        city: {
          select: {
            name: true,
            region: true,
          },
        },
        eventType: {
          select: {
            type: true,
          },
        },
      },
    });
  }
}
