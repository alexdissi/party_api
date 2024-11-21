/*
  Warnings:

  - You are about to drop the `BoardGameParty` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `Party` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `PartyContribution` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `PartyGame` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `PartyMessage` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `PartyParticipant` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `PartyRequestedItem` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `PartyReview` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `PartyType` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `VideoGameParty` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "BoardGameParty" DROP CONSTRAINT "BoardGameParty_partyId_fkey";

-- DropForeignKey
ALTER TABLE "Party" DROP CONSTRAINT "Party_cityId_fkey";

-- DropForeignKey
ALTER TABLE "Party" DROP CONSTRAINT "Party_organizerId_fkey";

-- DropForeignKey
ALTER TABLE "Party" DROP CONSTRAINT "Party_partyTypeId_fkey";

-- DropForeignKey
ALTER TABLE "PartyContribution" DROP CONSTRAINT "PartyContribution_partyId_fkey";

-- DropForeignKey
ALTER TABLE "PartyContribution" DROP CONSTRAINT "PartyContribution_requestedItemId_fkey";

-- DropForeignKey
ALTER TABLE "PartyContribution" DROP CONSTRAINT "PartyContribution_userId_fkey";

-- DropForeignKey
ALTER TABLE "PartyGame" DROP CONSTRAINT "PartyGame_partyId_fkey";

-- DropForeignKey
ALTER TABLE "PartyMessage" DROP CONSTRAINT "PartyMessage_partyId_fkey";

-- DropForeignKey
ALTER TABLE "PartyMessage" DROP CONSTRAINT "PartyMessage_senderId_fkey";

-- DropForeignKey
ALTER TABLE "PartyParticipant" DROP CONSTRAINT "PartyParticipant_partyId_fkey";

-- DropForeignKey
ALTER TABLE "PartyParticipant" DROP CONSTRAINT "PartyParticipant_userId_fkey";

-- DropForeignKey
ALTER TABLE "PartyRequestedItem" DROP CONSTRAINT "PartyRequestedItem_partyId_fkey";

-- DropForeignKey
ALTER TABLE "PartyReview" DROP CONSTRAINT "PartyReview_partyId_fkey";

-- DropForeignKey
ALTER TABLE "PartyReview" DROP CONSTRAINT "PartyReview_reviewedUserId_fkey";

-- DropForeignKey
ALTER TABLE "PartyReview" DROP CONSTRAINT "PartyReview_reviewerId_fkey";

-- DropForeignKey
ALTER TABLE "VideoGameParty" DROP CONSTRAINT "VideoGameParty_partyId_fkey";

-- DropTable
DROP TABLE "BoardGameParty";

-- DropTable
DROP TABLE "Party";

-- DropTable
DROP TABLE "PartyContribution";

-- DropTable
DROP TABLE "PartyGame";

-- DropTable
DROP TABLE "PartyMessage";

-- DropTable
DROP TABLE "PartyParticipant";

-- DropTable
DROP TABLE "PartyRequestedItem";

-- DropTable
DROP TABLE "PartyReview";

-- DropTable
DROP TABLE "PartyType";

-- DropTable
DROP TABLE "VideoGameParty";

-- CreateTable
CREATE TABLE "EventType" (
    "id" TEXT NOT NULL,
    "type" TEXT NOT NULL,

    CONSTRAINT "EventType_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Event" (
    "id" TEXT NOT NULL,
    "organizerId" TEXT NOT NULL,
    "eventTypeId" TEXT NOT NULL,
    "cityId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "address" TEXT NOT NULL,
    "dateTime" TIMESTAMP(3) NOT NULL,
    "maxParticipants" INTEGER NOT NULL,
    "isPaid" BOOLEAN NOT NULL,
    "price" DECIMAL(65,30),
    "description" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "Event_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BoardGameEvent" (
    "eventId" TEXT NOT NULL,
    "allowsGuestGames" BOOLEAN NOT NULL,

    CONSTRAINT "BoardGameEvent_pkey" PRIMARY KEY ("eventId")
);

-- CreateTable
CREATE TABLE "VideoGameEvent" (
    "eventId" TEXT NOT NULL,
    "platform" TEXT NOT NULL,
    "requiresEquipment" BOOLEAN NOT NULL,
    "availableEquipmentCount" INTEGER NOT NULL,

    CONSTRAINT "VideoGameEvent_pkey" PRIMARY KEY ("eventId")
);

-- CreateTable
CREATE TABLE "EventGame" (
    "id" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "minPlayers" INTEGER NOT NULL,
    "maxPlayers" INTEGER NOT NULL,
    "isGuestSuggestion" BOOLEAN NOT NULL,
    "votes" INTEGER NOT NULL,

    CONSTRAINT "EventGame_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EventParticipant" (
    "eventId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "paymentStatus" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EventParticipant_pkey" PRIMARY KEY ("eventId","userId")
);

-- CreateTable
CREATE TABLE "EventRequestedItem" (
    "id" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "itemName" TEXT NOT NULL,
    "quantity" INTEGER NOT NULL,
    "description" TEXT NOT NULL,

    CONSTRAINT "EventRequestedItem_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EventContribution" (
    "id" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "requestedItemId" TEXT NOT NULL,
    "itemName" TEXT NOT NULL,
    "quantity" INTEGER NOT NULL,
    "status" TEXT NOT NULL,

    CONSTRAINT "EventContribution_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EventReview" (
    "id" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "reviewerId" TEXT NOT NULL,
    "reviewedUserId" TEXT NOT NULL,
    "rating" INTEGER NOT NULL,
    "comment" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EventReview_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EventMessage" (
    "id" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "senderId" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EventMessage_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "Event" ADD CONSTRAINT "Event_organizerId_fkey" FOREIGN KEY ("organizerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Event" ADD CONSTRAINT "Event_eventTypeId_fkey" FOREIGN KEY ("eventTypeId") REFERENCES "EventType"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Event" ADD CONSTRAINT "Event_cityId_fkey" FOREIGN KEY ("cityId") REFERENCES "City"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BoardGameEvent" ADD CONSTRAINT "BoardGameEvent_eventId_fkey" FOREIGN KEY ("eventId") REFERENCES "Event"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VideoGameEvent" ADD CONSTRAINT "VideoGameEvent_eventId_fkey" FOREIGN KEY ("eventId") REFERENCES "Event"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EventGame" ADD CONSTRAINT "EventGame_eventId_fkey" FOREIGN KEY ("eventId") REFERENCES "Event"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EventParticipant" ADD CONSTRAINT "EventParticipant_eventId_fkey" FOREIGN KEY ("eventId") REFERENCES "Event"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EventParticipant" ADD CONSTRAINT "EventParticipant_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EventRequestedItem" ADD CONSTRAINT "EventRequestedItem_eventId_fkey" FOREIGN KEY ("eventId") REFERENCES "Event"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EventContribution" ADD CONSTRAINT "EventContribution_eventId_fkey" FOREIGN KEY ("eventId") REFERENCES "Event"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EventContribution" ADD CONSTRAINT "EventContribution_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EventContribution" ADD CONSTRAINT "EventContribution_requestedItemId_fkey" FOREIGN KEY ("requestedItemId") REFERENCES "EventRequestedItem"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EventReview" ADD CONSTRAINT "EventReview_eventId_fkey" FOREIGN KEY ("eventId") REFERENCES "Event"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EventReview" ADD CONSTRAINT "EventReview_reviewerId_fkey" FOREIGN KEY ("reviewerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EventReview" ADD CONSTRAINT "EventReview_reviewedUserId_fkey" FOREIGN KEY ("reviewedUserId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EventMessage" ADD CONSTRAINT "EventMessage_eventId_fkey" FOREIGN KEY ("eventId") REFERENCES "Event"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EventMessage" ADD CONSTRAINT "EventMessage_senderId_fkey" FOREIGN KEY ("senderId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
