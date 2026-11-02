// SP1-PA3C-Q1: registers node-ts-resolve-hook.mjs so plain `node --import <this file> <script>.ts` runs the observer
// path's TypeScript with Node's own type stripping and no npm package at all (the clean container's execution path).
import { register } from "node:module";

register("./node-ts-resolve-hook.mjs", import.meta.url);
