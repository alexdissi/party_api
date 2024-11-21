-- DropIndex
DROP INDEX "Event_name_key";

-- AlterTable
ALTER TABLE "Event" ALTER COLUMN "name" SET DATA TYPE TEXT;
