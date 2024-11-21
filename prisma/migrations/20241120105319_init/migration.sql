/*
  Warnings:

  - The primary key for the `PartyParticipant` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `User` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - The primary key for the `UserInterest` table will be changed. If it partially fails, the table could be left without primary key constraint.

*/
-- DropForeignKey
ALTER TABLE "Party" DROP CONSTRAINT "Party_organizerId_fkey";

-- DropForeignKey
ALTER TABLE "PartyContribution" DROP CONSTRAINT "PartyContribution_userId_fkey";

-- DropForeignKey
ALTER TABLE "PartyMessage" DROP CONSTRAINT "PartyMessage_senderId_fkey";

-- DropForeignKey
ALTER TABLE "PartyParticipant" DROP CONSTRAINT "PartyParticipant_userId_fkey";

-- DropForeignKey
ALTER TABLE "PartyReview" DROP CONSTRAINT "PartyReview_reviewedUserId_fkey";

-- DropForeignKey
ALTER TABLE "PartyReview" DROP CONSTRAINT "PartyReview_reviewerId_fkey";

-- DropForeignKey
ALTER TABLE "UserInterest" DROP CONSTRAINT "UserInterest_userId_fkey";

-- DropForeignKey
ALTER TABLE "UserReview" DROP CONSTRAINT "UserReview_reviewedUserId_fkey";

-- DropForeignKey
ALTER TABLE "UserReview" DROP CONSTRAINT "UserReview_reviewerId_fkey";

-- AlterTable
ALTER TABLE "Party" ALTER COLUMN "organizerId" SET DATA TYPE TEXT;

-- AlterTable
ALTER TABLE "PartyContribution" ALTER COLUMN "userId" SET DATA TYPE TEXT;

-- AlterTable
ALTER TABLE "PartyMessage" ALTER COLUMN "senderId" SET DATA TYPE TEXT;

-- AlterTable
ALTER TABLE "PartyParticipant" DROP CONSTRAINT "PartyParticipant_pkey",
ALTER COLUMN "userId" SET DATA TYPE TEXT,
ADD CONSTRAINT "PartyParticipant_pkey" PRIMARY KEY ("partyId", "userId");

-- AlterTable
ALTER TABLE "PartyReview" ALTER COLUMN "reviewerId" SET DATA TYPE TEXT,
ALTER COLUMN "reviewedUserId" SET DATA TYPE TEXT;

-- AlterTable
ALTER TABLE "User" DROP CONSTRAINT "User_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ADD CONSTRAINT "User_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "User_id_seq";

-- AlterTable
ALTER TABLE "UserInterest" DROP CONSTRAINT "UserInterest_pkey",
ALTER COLUMN "userId" SET DATA TYPE TEXT,
ADD CONSTRAINT "UserInterest_pkey" PRIMARY KEY ("userId", "interestType");

-- AlterTable
ALTER TABLE "UserReview" ALTER COLUMN "reviewerId" SET DATA TYPE TEXT,
ALTER COLUMN "reviewedUserId" SET DATA TYPE TEXT;

-- AddForeignKey
ALTER TABLE "UserInterest" ADD CONSTRAINT "UserInterest_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Party" ADD CONSTRAINT "Party_organizerId_fkey" FOREIGN KEY ("organizerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyParticipant" ADD CONSTRAINT "PartyParticipant_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyContribution" ADD CONSTRAINT "PartyContribution_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserReview" ADD CONSTRAINT "UserReview_reviewerId_fkey" FOREIGN KEY ("reviewerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserReview" ADD CONSTRAINT "UserReview_reviewedUserId_fkey" FOREIGN KEY ("reviewedUserId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyReview" ADD CONSTRAINT "PartyReview_reviewerId_fkey" FOREIGN KEY ("reviewerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyReview" ADD CONSTRAINT "PartyReview_reviewedUserId_fkey" FOREIGN KEY ("reviewedUserId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PartyMessage" ADD CONSTRAINT "PartyMessage_senderId_fkey" FOREIGN KEY ("senderId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
