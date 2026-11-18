import { redirect } from "next/navigation";

export default function ProtocolHome() {
  redirect("/protocol/cases");
  return null;
}