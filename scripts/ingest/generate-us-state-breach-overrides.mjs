import path from "node:path";

import { projectRoot, readJson, writeJson } from "./lib/dataset-files.mjs";

const usStatesPath = path.join(projectRoot, "ingestion", "reference", "us_states.json");
const outputPath = path.join(projectRoot, "ingestion", "reference", "us_state_breach_overrides.json");
const ncslSourceUrl = "https://www.ncsl.org/technology-and-communication/security-breach-notification-laws";

const statuteRefs = {
  "US-AL": "Ala. Code § 8-38-1 et seq.",
  "US-AK": "Alaska Stat. § 45.48.010 et seq.",
  "US-AZ": "Ariz. Rev. Stat. § 18-551 to -552",
  "US-AR": "Ark. Code §§ 4-110-101 et seq.",
  "US-CA": "Cal. Civ. Code § 1798.82",
  "US-CO": "Colo. Rev. Stat. § 6-1-716",
  "US-CT": "Conn. Gen. Stat. § 36a-701b",
  "US-DE": "Del. Code tit. 6, § 12B-101 et seq.",
  "US-FL": "Fla. Stat. § 501.171",
  "US-GA": "Ga. Code §§ 10-1-910 to -912; 46-5-214",
  "US-HI": "Haw. Rev. Stat. § 487N-1 et seq.",
  "US-ID": "Idaho Stat. §§ 28-51-104 to -107",
  "US-IL": "815 ILCS §§ 530/1 to 530/25",
  "US-IN": "Ind. Code § 24-4.9 et seq.",
  "US-IA": "Iowa Code §§ 715C.1, 715C.2",
  "US-KS": "Kan. Stat. § 50-7a01 et seq.",
  "US-KY": "KRS § 365.732",
  "US-LA": "La. Rev. Stat. §§ 51:3071 et seq.",
  "US-ME": "Me. Rev. Stat. tit. 10 § 1346 et seq.",
  "US-MD": "Md. Code Com. Law § 14-3504",
  "US-MA": "Mass. Gen. Laws ch. 93H, § 1 et seq.",
  "US-MI": "Mich. Comp. Laws §§ 445.63, 445.72",
  "US-MN": "Minn. Stat. §§ 325E.61, 325E.64",
  "US-MS": "Miss. Code § 75-24-29",
  "US-MO": "Mo. Rev. Stat. § 407.1500",
  "US-MT": "Mont. Code § 30-14-1704",
  "US-NE": "Neb. Rev. Stat. §§ 87-801 et seq.",
  "US-NV": "Nev. Rev. Stat. §§ 603A.010 et seq.",
  "US-NH": "N.H. Rev. Stat. §§ 359-C:19, 359-C:20, 359-C:21",
  "US-NJ": "N.J. Stat. § 56:8-161 et seq.",
  "US-NM": "N.M. Stat. §§ 57-12C-1 et seq.",
  "US-NY": "N.Y. Gen. Bus. Law § 899-AA",
  "US-NC": "N.C. Gen. Stat. §§ 75-61, 75-65",
  "US-ND": "N.D. Cent. Code §§ 51-30-01 et seq.",
  "US-OH": "Ohio Rev. Code §§ 1349.19, 1349.191",
  "US-OK": "Okla. Stat. §§ 24-161 to -166",
  "US-OR": "Or. Rev. Stat. §§ 646A.600 to 646A.628",
  "US-PA": "73 Pa. Stat. § 2301 et seq.",
  "US-RI": "R.I. Gen. Laws § 11-49.3-1 et seq.",
  "US-SC": "S.C. Code § 39-1-90",
  "US-SD": "S.D. Codified Laws §§ 22-40-19 to -26",
  "US-TN": "Tenn. Code § 47-18-2107",
  "US-TX": "Tex. Bus. & Com. Code §§ 521.002, 521.053",
  "US-UT": "Utah Code § 13-44-101 et seq.",
  "US-VT": "Vt. Stat. tit. 9 §§ 2430, 2435",
  "US-VA": "Va. Code § 18.2-186.6",
  "US-WA": "Wash. Rev. Code § 19.255.010",
  "US-WV": "W. Va. Code § 46A-2A-101 et seq.",
  "US-WI": "Wis. Stat. § 134.98",
  "US-WY": "Wyo. Stat. §§ 40-12-501 to -502",
  "US-DC": "D.C. Code §§ 28-3851 et seq."
};

const deadlines = {
  "US-CO": "not later than 30 days after determination",
  "US-FL": "within 30 days after determination",
  "US-TX": "without unreasonable delay and not later than 60 days"
};

const thresholds = {
  "US-CA": "more than 500 residents",
  "US-CO": "500 residents for AG notice",
  "US-CT": "500 residents for AG notice",
  "US-FL": "500 residents for regulator notice",
  "US-IL": "500 residents for AG notice",
  "US-MA": "state regulator notice required",
  "US-NY": "state agencies and AG notice as required",
  "US-TX": "250 residents for AG notice",
  "US-WA": "500 residents for AG notice"
};

const regulatorNotices = {
  "US-CA": "California Attorney General",
  "US-CO": "Colorado Attorney General",
  "US-CT": "Connecticut Attorney General",
  "US-FL": "Florida Department of Legal Affairs",
  "US-IL": "Illinois Attorney General",
  "US-MA": "Massachusetts AG and OCABR",
  "US-NY": "New York AG and designated state agencies",
  "US-TX": "Texas Attorney General",
  "US-WA": "Washington Attorney General"
};

const curatedPrimaryOverrides = {
  "US-CA": {
    statute_ref: "Cal. Civ. Code 1798.82",
    deadline: "without unreasonable delay",
    ag_notice_threshold: "more than 500 California residents",
    regulator_notice: "California Attorney General when threshold met",
    source_url: "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.82.&lawCode=CIV",
    source_tier: "primary",
    confidence: "authoritative",
    profile_source: "primary-statute-curated"
  },
  "US-NY": {
    statute_ref: "Gen. Bus. Law § 899-aa",
    deadline: "in the most expedient time possible and without unreasonable delay",
    ag_notice_threshold: "state-designated regulator notification required when applicable",
    regulator_notice: "New York Attorney General and other designated agencies",
    source_url: "https://www.nysenate.gov/legislation/laws/GBS/899-AA",
    source_tier: "primary",
    confidence: "authoritative",
    profile_source: "primary-statute-curated"
  },
  "US-TX": {
    statute_ref: "Tex. Bus. & Com. Code § 521.053",
    deadline: "without unreasonable delay and not later than 60 days",
    ag_notice_threshold: "at least 250 Texas residents",
    regulator_notice: "Texas Attorney General when threshold met",
    source_url: "https://statutes.capitol.texas.gov/Docs/BC/htm/BC.521.htm",
    source_tier: "primary",
    confidence: "authoritative",
    profile_source: "primary-statute-curated"
  },
  "US-FL": {
    statute_ref: "Fla. Stat. § 501.171",
    deadline: "within 30 days after determination of breach",
    ag_notice_threshold: "at least 500 Florida residents",
    regulator_notice: "Florida Department of Legal Affairs",
    source_url: "https://www.flsenate.gov/Laws/Statutes/2024/501.171",
    source_tier: "primary",
    confidence: "authoritative",
    profile_source: "primary-statute-curated"
  },
  "US-WA": {
    statute_ref: "RCW 19.255.010",
    deadline: "most expedient time possible and without unreasonable delay",
    ag_notice_threshold: "at least 500 Washington residents",
    regulator_notice: "Washington Attorney General",
    source_url: "https://app.leg.wa.gov/rcw/default.aspx?cite=19.255.010",
    source_tier: "primary",
    confidence: "authoritative",
    profile_source: "primary-statute-curated"
  },
  "US-MA": {
    statute_ref: "Mass. Gen. Laws ch. 93H § 3",
    deadline: "as soon as practicable and without unreasonable delay",
    ag_notice_threshold: "regulator notification required for reportable breaches",
    regulator_notice: "Massachusetts Attorney General and Office of Consumer Affairs",
    source_url: "https://malegislature.gov/Laws/GeneralLaws/PartI/TitleXV/Chapter93H/Section3",
    source_tier: "primary",
    confidence: "authoritative",
    profile_source: "primary-statute-curated"
  },
  "US-IL": {
    statute_ref: "815 ILCS 530/10",
    deadline: "in the most expedient time possible and without unreasonable delay",
    ag_notice_threshold: "at least 500 Illinois residents",
    regulator_notice: "Illinois Attorney General when threshold met",
    source_url: "https://www.ilga.gov/legislation/ilcs/ilcs3.asp?ActID=3004&ChapterID=57",
    source_tier: "primary",
    confidence: "authoritative",
    profile_source: "primary-statute-curated"
  },
  "US-CO": {
    statute_ref: "C.R.S. 6-1-716",
    deadline: "not later than 30 days after determination",
    ag_notice_threshold: "at least 500 Colorado residents",
    regulator_notice: "Colorado Attorney General",
    source_url: "https://leg.colorado.gov/sites/default/files/images/olls/crs2024-title-6.pdf",
    source_tier: "primary",
    confidence: "authoritative",
    profile_source: "primary-statute-curated"
  },
  "US-CT": {
    statute_ref: "Conn. Gen. Stat. § 36a-701b",
    deadline: "without unreasonable delay",
    ag_notice_threshold: "at least 500 Connecticut residents",
    regulator_notice: "Connecticut Attorney General",
    source_url: "https://www.cga.ct.gov/current/pub/chap_668.htm#sec_36a-701b",
    source_tier: "primary",
    confidence: "authoritative",
    profile_source: "primary-statute-curated"
  },
  "US-NJ": {
    statute_ref: "N.J. Stat. § 56:8-163",
    deadline: "in the most expedient time possible and without unreasonable delay",
    ag_notice_threshold: "law-enforcement and state reporting as required",
    regulator_notice: "New Jersey State Police and consumer affairs authorities",
    source_url: "https://www.njleg.state.nj.us/bill-search/2022/A3000/bill-text?f=A3000&n=2978_I1",
    source_tier: "primary",
    confidence: "authoritative",
    profile_source: "primary-statute-curated"
  }
};

async function main() {
  const states = await readJson(usStatesPath);
  const output = {};
  for (const state of states) {
    const code = state.replace(/^US-/, "").toLowerCase();
    if (!statuteRefs[state]) {
      throw new Error(`Missing statute reference for ${state}.`);
    }
    const primary = curatedPrimaryOverrides[state] ?? {};
    output[state] = {
      statute_ref: primary.statute_ref ?? statuteRefs[state],
      deadline: primary.deadline ?? deadlines[state] ?? "without unreasonable delay",
      ag_notice_threshold:
        primary.ag_notice_threshold ?? thresholds[state] ?? "state-specific threshold conditions",
      regulator_notice:
        primary.regulator_notice ?? regulatorNotices[state] ?? "state attorney general or designated state authority",
      source_url: primary.source_url ?? ncslSourceUrl,
      law_mcp_document_id: `us-${code}-breach-notification`,
      law_mcp_provision_ref: "main",
      effective_from: "2003-01-01",
      effective_to: null,
      penalties: "state enforcement, civil penalties, and/or private rights of action depending on jurisdiction",
      source_tier: primary.source_tier ?? "secondary",
      confidence: primary.confidence ?? "estimated",
      profile_source: primary.profile_source ?? "ncsl-derived-default"
    };
  }
  await writeJson(outputPath, output);
  process.stdout.write(`Wrote ${outputPath}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
});
