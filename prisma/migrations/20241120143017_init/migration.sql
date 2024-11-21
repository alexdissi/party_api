/*
  Warnings:

  - The primary key for the `BoardGameParty` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `Party` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `city` on the `Party` table. All the data in the column will be lost.
  - You are about to drop the column `partyType` on the `Party` table. All the data in the column will be lost.
  - The primary key for the `PartyContribution` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `PartyGame` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `PartyMessage` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `PartyParticipant` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The `paymentStatus` column on the `PartyParticipant` table would be dropped and recreated. This will lead to data loss if there is data in the column.
  - The primary key for the `PartyRequestedItem` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `PartyReview` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `city` on the `User` table. All the data in the column will be lost.
  - You are about to drop the column `region` on the `User` table. All the data in the column will be lost.
  - The primary key for the `UserInterest` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `interestType` on the `UserInterest` table. All the data in the column will be lost.
  - The primary key for the `UserReview` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `VideoGameParty` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - Added the required column `cityId` to the `Party` table without a default value. This is not possible if the table is not empty.
  - Added the required column `partyTypeId` to the `Party` table without a default value. This is not possible if the table is not empty.
  - Changed the type of `status` on the `PartyContribution` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.
  - Changed the type of `status` on the `PartyParticipant` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.
  - Added the required column `interestTypeId` to the `UserInterest` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "BoardGameParty" DROP CONSTRAINT "BoardGameParty_partyId_fkey";

-- DropForeignKey
ALTER TABLE "PartyContribution" DROP CONSTRAINT "PartyContribution_partyId_fkey";

-- DropForeignKey
ALTER TABLE "PartyContribution" DROP CONSTRAINT "PartyContribution_requestedItemId_fkey";

-- DropForeignKey
ALTER TABLE "PartyGame" DROP CONSTRAINT "PartyGame_partyId_fkey";

-- DropForeignKey
ALTER TABLE "PartyMessage" DROP CONSTRAINT "PartyMessage_partyId_fkey";

-- DropForeignKey
ALTER TABLE "PartyParticipant" DROP CONSTRAINT "PartyParticipant_partyId_fkey";

-- DropForeignKey
ALTER TABLE "PartyRequestedItem" DROP CONSTRAINT "PartyRequestedItem_partyId_fkey";

-- DropForeignKey
ALTER TABLE "PartyReview" DROP CONSTRAINT "PartyReview_partyId_fkey";

-- DropForeignKey
ALTER TABLE "VideoGameParty" DROP CONSTRAINT "VideoGameParty_partyId_fkey";

-- AlterTable
ALTER TABLE "BoardGameParty" DROP CONSTRAINT "BoardGameParty_pkey",
ALTER COLUMN "partyId" SET DATA TYPE TEXT,
ADD CONSTRAINT "BoardGameParty_pkey" PRIMARY KEY ("partyId");

-- AlterTable
ALTER TABLE "Party" DROP CONSTRAINT "Party_pkey",
DROP COLUMN "city",
DROP COLUMN "partyType",
ADD COLUMN     "cityId" TEXT NOT NULL,
ADD COLUMN     "partyTypeId" TEXT NOT NULL,
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ADD CONSTRAINT "Party_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "Party_id_seq";

-- AlterTable
ALTER TABLE "PartyContribution" DROP CONSTRAINT "PartyContribution_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ALTER COLUMN "partyId" SET DATA TYPE TEXT,
ALTER COLUMN "requestedItemId" SET DATA TYPE TEXT,
DROP COLUMN "status",
ADD COLUMN     "status" TEXT NOT NULL,
ADD CONSTRAINT "PartyContribution_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "PartyContribution_id_seq";

-- AlterTable
ALTER TABLE "PartyGame" DROP CONSTRAINT "PartyGame_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ALTER COLUMN "partyId" SET DATA TYPE TEXT,
ADD CONSTRAINT "PartyGame_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "PartyGame_id_seq";

-- AlterTable
ALTER TABLE "PartyMessage" DROP CONSTRAINT "PartyMessage_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ALTER COLUMN "partyId" SET DATA TYPE TEXT,
ADD CONSTRAINT "PartyMessage_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "PartyMessage_id_seq";

-- AlterTable
ALTER TABLE "PartyParticipant" DROP CONSTRAINT "PartyParticipant_pkey",
ALTER COLUMN "partyId" SET DATA TYPE TEXT,
DROP COLUMN "status",
ADD COLUMN     "status" TEXT NOT NULL,
DROP COLUMN "paymentStatus",
ADD COLUMN     "paymentStatus" TEXT,
ADD CONSTRAINT "PartyParticipant_pkey" PRIMARY KEY ("partyId", "userId");

-- AlterTable
ALTER TABLE "PartyRequestedItem" DROP CONSTRAINT "PartyRequestedItem_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ALTER COLUMN "partyId" SET DATA TYPE TEXT,
ADD CONSTRAINT "PartyRequestedItem_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "PartyRequestedItem_id_seq";

-- AlterTable
ALTER TABLE "PartyReview" DROP CONSTRAINT "PartyReview_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ALTER COLUMN "partyId" SET DATA TYPE TEXT,
ADD CONSTRAINT "PartyReview_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "PartyReview_id_seq";

-- AlterTable
ALTER TABLE "User" DROP COLUMN "city",
DROP COLUMN "region",
ADD COLUMN     "cityId" TEXT;

-- AlterTable
ALTER TABLE "UserInterest" DROP CONSTRAINT "UserInterest_pkey",
DROP COLUMN "interestType",
ADD COLUMN     "interestTypeId" TEXT NOT NULL,
ADD CONSTRAINT "UserInterest_pkey" PRIMARY KEY ("userId", "interestTypeId");

-- AlterTable
ALTER TABLE "UserReview" DROP CONSTRAINT "UserReview_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ADD CONSTRAINT "UserReview_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "UserReview_id_seq";

-- AlterTable
ALTER TABLE "VideoGameParty" DROP CONSTRAINT "VideoGameParty_pkey",
ALTER COLUMN "partyId" SET DATA TYPE TEXT,
ADD CONSTRAINT "VideoGameParty_pkey" PRIMARY KEY ("partyId");

-- DropEnum
DROP TYPE "ContributionStatus";

-- DropEnum
DROP TYPE "InterestType";

-- DropEnum
DROP TYPE "ParticipantStatus";

-- DropEnum
DROP TYPE "PartyType";

-- DropEnum
DROP TYPE "PaymentStatus";

-- DropEnum
DROP TYPE "UserType";

-- CreateTable
CREATE TABLE "City" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "region" TEXT NOT NULL,

    CONSTRAINT "City_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserType" (
    "id" TEXT NOT NULL,
    "type" TEXT NOT NULL,

    CONSTRAINT "UserType_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PartyType" (
    "id" TEXT NOT NULL,
    "type" TEXT NOT NULL,

    CONSTRAINT "PartyType_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "InterestType" (
    "id" TEXT NOT NULL,
    "type" TEXT NOT NULL,

    CONSTRAINT "InterestType_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "User" ADD CONSTRAINT "User_cityId_fkey" FOREIGN KEY ("cityId") REFERENCES "City"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserInterest" ADD CONSTRAINT "UserInterest_interestTypeId_fkey" FOREIGN KEY ("interestTypeId") REFERENCES "InterestType"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Party" ADD CONSTRAINT "Party_partyTypeId_fkey" FOREIGN KEY ("partyTypeId") REFERENCES "PartyType"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Party" ADD CONSTRAINT "Party_cityId_fkey" FOREIGN KEY ("cityId") REFERENCES "City"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BoardGameParty" ADD CONSTRAINT "BoardGameParty_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "VideoGameParty" ADD CONSTRAINT "VideoGameParty_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyGame" ADD CONSTRAINT "PartyGame_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyParticipant" ADD CONSTRAINT "PartyParticipant_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyRequestedItem" ADD CONSTRAINT "PartyRequestedItem_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyContribution" ADD CONSTRAINT "PartyContribution_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyContribution" ADD CONSTRAINT "PartyContribution_requestedItemId_fkey" FOREIGN KEY ("requestedItemId") REFERENCES "PartyRequestedItem"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyReview" ADD CONSTRAINT "PartyReview_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyMessage" ADD CONSTRAINT "PartyMessage_partyId_fkey" FOREIGN KEY ("partyId") REFERENCES "Party"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
