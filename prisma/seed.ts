import { PrismaClient } from '@prisma/client';
import { faker } from '@faker-js/faker';

const prisma = new PrismaClient();

async function seed() {
  const users = await prisma.user.findMany({ select: { id: true } });
  const eventTypes = await prisma.eventType.findMany({ select: { id: true } });
  const cities = await prisma.city.findMany({ select: { id: true } });


  const eventsData = Array.from({ length: 100000 }).map(() => {
    const randomOrganizer = users[Math.floor(Math.random() * users.length)];
    const randomEventType = eventTypes[Math.floor(Math.random() * eventTypes.length)];
    const randomCity = cities[Math.floor(Math.random() * cities.length)];

    return {
      organizerId: randomOrganizer.id,
      eventTypeId: randomEventType.id,
      cityId: randomCity.id,
      name: faker.lorem.words(3),
      address: faker.location.streetAddress(),
      dateTime: faker.date.future(),
      maxParticipants: faker.number.int({ min: 10, max: 100 }),
      isPaid: faker.datatype.boolean(),
      price: faker.number.int({ min: 10, max: 1000 }), 
      description: faker.lorem.paragraph(),
    };
  });

  const BATCH_SIZE = 5000; 
  for (let i = 0; i < eventsData.length; i += BATCH_SIZE) {
    const batch = eventsData.slice(i, i + BATCH_SIZE);
    await prisma.event.createMany({
      data: batch,
    });
    console.log(`Batch ${i / BATCH_SIZE + 1} inserted`);
  }

  console.log('Seeding completed!');
}

seed()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
