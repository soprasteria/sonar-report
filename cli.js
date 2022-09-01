#!/usr/bin/env node
import { buildCommand, generateReport } from "./index.js";

generateReport(buildCommand().parse().opts());
