/*
  Warnings:

  - The primary key for the `User` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `dateResetPassword` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `isResettingPassword` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `name` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `password` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `profilePictureUrl` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `resetPasswordToken` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `role` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `status` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `stripeCustomerId` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `stripeUserPlan` on the `User` table. All the data in the column will be lost.
  - The `id` column on the `User` table would be dropped and recreated. This will lead to data loss if there is data in the column.
  - Added the required column `age` to the `User` table without a default value. This is not possible if the table is not empty.
  - Added the required column `city` to the `User` table without a default value. This is not possible if the table is not empty.
  - Added the required column `passwordHash` to the `User` table without a default value. This is not possible if the table is not empty.
  - Added the required column `rating` to the `User` table without a default value. This is not possible if the table is not empty.
  - Added the required column `region` to the `User` table without a default value. This is not possible if the table is not empty.
  - Added the required column `updatedAt` to the `User` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "UserType" AS ENUM ('ORGANIZER', 'PARTICIPANT');

-- CreateEnum
CREATE TYPE "PartyType" AS ENUM ('BOARD_GAME', 'VIDEO_GAME', 'CLASSIC');

-- CreateEnum
CREATE TYPE "InterestType" AS ENUM ('BOARD_GAMES', 'VIDEO_GAMES', 'CLUBBING', 'DRINKING', 'OTHER');

-- CreateEnum
CREATE TYPE "ParticipantStatus" AS ENUM ('PENDING', 'ACCEPTED', 'REJECTED');

-- CreateEnum
CREATE TYPE "PaymentStatus" AS ENUM ('PENDING', 'COMPLETED', 'FAILED');

-- CreateEnum
CREATE TYPE "ContributionStatus" AS ENUM ('PENDING', 'CONFIRMED');

-- DropIndex
DROP INDEX "User_resetPasswordToken_key";

-- AlterTable
ALTER TABLE "User" DROP CONSTRAINT "User_pkey",
DROP COLUMN "dateResetPassword",
DROP COLUMN "isResettingPassword",
DROP COLUMN "name",
DROP COLUMN "password",
DROP COLUMN "profilePictureUrl",
DROP COLUMN "resetPasswordToken",
DROP COLUMN "role",
DROP COLUMN "status",
DROP COLUMN "stripeCustomerId",
DROP COLUMN "stripeUserPlan",
ADD COLUMN     "age" INTEGER NOT NULL,
ADD COLUMN     "city" TEXT NOT NULL,
ADD COLUMN     "deletedAt" TIMESTAMP(3),
ADD COLUMN     "passwordHash" TEXT NOT NULL,
ADD COLUMN     "rating" DECIMAL(65,30) NOT NULL,
ADD COLUMN     "region" TEXT NOT NULL,
ADD COLUMN     "updatedAt" TIMESTAMP(3) NOT NULL,
DROP COLUMN "id",
ADD COLUMN     "id" SERIAL NOT NULL,
ADD CONSTRAINT "User_pkey" PRIMARY KEY ("id");

-- DropEnum
DROP TYPE "Status";

-- DropEnum
DROP TYPE "UserPlan";

-- DropEnum
DROP TYPE "UserRoles";

-- CreateTable
CREATE TABLE "UserInterest" (
    "userId" INTEGER NOT NULL,
    "interestType" "InterestType" NOT NULL,

    CONSTRAINT "UserInterest_pkey" PRIMARY KEY ("userId","interestType")
);

-- CreateTable
CREATE TABLE "Party" (
    "id" SERIAL NOT NULL,
    "organizerId" INTEGER NOT NULL,
    "partyType" "PartyType" NOT NULL,
    "name" TEXT NOT NULL,
    "city" TEXT NOT NULL,
    "address" TEXT NOT NULL,
    "dateTime" TIMESTAMP(3) NOT NULL,
    "maxParticipants" INTEGER NOT NULL,
    "isPaid" BOOLEAN NOT NULL,
    "price" DECIMAL(65,30),
    "description" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "Party_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BoardGameParty" (
    "partyId" INTEGER NOT NULL,
    "allowsGuestGames" BOOLEAN NOT NULL,

    CONSTRAINT "BoardGameParty_pkey" PRIMARY KEY ("partyId")
);

-- CreateTable
CREATE TABLE "VideoGameParty" (
    "partyId" INTEGER NOT NULL,
    "platform" TEXT NOT NULL,
    "requiresEquipment" BOOLEAN NOT NULL,
    "availableEquipmentCount" INTEGER NOT NULL,

    CONSTRAINT "VideoGameParty_pkey" PRIMARY KEY ("partyId")
);

-- CreateTable
CREATE TABLE "PartyGame" (
    "id" SERIAL NOT NULL,
    "partyId" INTEGER NOT NULL,
    "name" TEXT NOT NULL,
    "minPlayers" INTEGER NOT NULL,
    "maxPlayers" INTEGER NOT NULL,
    "isGuestSuggestion" BOOLEAN NOT NULL,
    "votes" INTEGER NOT NULL,

    CONSTRAINT "PartyGame_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PartyParticipant" (
    "partyId" INTEGER NOT NULL,
    "userId" INTEGER NOT NULL,
    "status" "ParticipantStatus" NOT NULL,
    "paymentStatus" "PaymentStatus",
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PartyParticipant_pkey" PRIMARY KEY ("partyId","userId")
);

-- CreateTable
CREATE TABLE "PartyRequestedItem" (
    "id" SERIAL NOT NULL,
    "partyId" INTEGER NOT NULL,
    "itemName" TEXT NOT NULL,
    "quantity" INTEGER NOT NULL,
    "description" TEXT NOT NULL,

    CONSTRAINT "PartyRequestedItem_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PartyContribution" (
    "id" SERIAL NOT NULL,
    "partyId" INTEGER NOT NULL,
    "userId" INTEGER NOT NULL,
    "requestedItemId" INTEGER NOT NULL,
    "itemName" TEXT NOT NULL,
    "quantity" INTEGER NOT NULL,
    "status" "ContributionStatus" NOT NULL,

    CONSTRAINT "PartyContribution_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserReview" (
    "id" SERIAL NOT NULL,
    "reviewerId" INTEGER NOT NULL,
    "reviewedUserId" INTEGER NOT NULL,
    "rating" INTEGER NOT NULL,
    "comment" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UserReview_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PartyReview" (
    "id" SERIAL NOT NULL,
    "partyId" INTEGER NOT NULL,
    "reviewerId" INTEGER NOT NULL,
    "reviewedUserId" INTEGER NOT NULL,
    "rating" INTEGER NOT NULL,
    "comment" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PartyReview_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PartyMessage" (
    "id" SERIAL NOT NULL,
    "partyId" INTEGER NOT NULL,
    "senderId" INTEGER NOT NULL,
    "message" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PartyMessage_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "UserInterest" ADD CONSTRAINT "UserInterest_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Party" ADD CONSTRAINT "Party_organizerId_fkey" FOREIGN KEY ("organizerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BoardGameParty" ADD CONSTRAINT "BoardGameParty_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VideoGameParty" ADD CONSTRAINT "VideoGameParty_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyGame" ADD CONSTRAINT "PartyGame_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyParticipant" ADD CONSTRAINT "PartyParticipant_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyParticipant" ADD CONSTRAINT "PartyParticipant_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyRequestedItem" ADD CONSTRAINT "PartyRequestedItem_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyContribution" ADD CONSTRAINT "PartyContribution_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyContribution" ADD CONSTRAINT "PartyContribution_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyContribution" ADD CONSTRAINT "PartyContribution_requestedItemId_fkey" FOREIGN KEY ("requestedItemId") REFERENCES "PartyRequestedItem"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserReview" ADD CONSTRAINT "UserReview_reviewerId_fkey" FOREIGN KEY ("reviewerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserReview" ADD CONSTRAINT "UserReview_reviewedUserId_fkey" FOREIGN KEY ("reviewedUserId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyReview" ADD CONSTRAINT "PartyReview_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyReview" ADD CONSTRAINT "PartyReview_reviewerId_fkey" FOREIGN KEY ("reviewerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyReview" ADD CONSTRAINT "PartyReview_reviewedUserId_fkey" FOREIGN KEY ("reviewedUserId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyMessage" ADD CONSTRAINT "PartyMessage_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyMessage" ADD CONSTRAINT "PartyMessage_senderId_fkey" FOREIGN KEY ("senderId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
