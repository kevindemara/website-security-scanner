class EmailSecurityChecker {
  async queryDns(domain, signal) {
    const data = await globalThis.ScannerCore.request(
      "https://dns.google/resolve?name=" +
        encodeURIComponent(domain) +
        "&type=TXT",
      {},
      { signal },
    );
    if (![0, 3].includes(data.Status))
      throw new Error("DNS lookup failed; record presence is unknown.");
    return (data.Answer || [])
      .filter((answer) => answer.type === 16)
      .slice(0, 100)
      .map((answer) =>
        String(answer.data)
          .replace(/"\s*"/g, "")
          .replace(/^"|"$/g, "")
          .slice(0, 2000),
      );
  }
  async checkDomain(domain, signal) {
    const C = globalThis.ScannerCore;
    const [txt, dmarcTxt] = await Promise.all([
      this.queryDns(domain, signal),
      this.queryDns("_dmarc." + domain, signal),
    ]);
    const spf = txt.filter((record) => /^v=spf1(?:\s|$)/i.test(record));
    const dmarc = dmarcTxt.filter((record) => /^v=DMARC1\s*;/i.test(record));
    const recommendations = [];
    if (spf.length !== 1)
      recommendations.push(
        "Publish exactly one SPF record for the checked hostname.",
      );
    if (dmarc.length !== 1)
      recommendations.push(
        "Publish exactly one DMARC record for the checked hostname.",
      );
    const spfStrict = spf.length === 1 && /(?:^|\s)-all\s*$/i.test(spf[0]);
    const policy = dmarc[0]
      ?.match(/(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\s*(?:;|$)/i)?.[1]
      ?.toLowerCase();
    if (spf.length === 1 && !spfStrict)
      recommendations.push(
        "Review the SPF ending policy; -all rejects unauthorized senders.",
      );
    if (dmarc.length === 1 && !policy)
      recommendations.push("Add a valid DMARC p= policy.");
    if (policy === "none")
      recommendations.push(
        "DMARC is monitoring only. Consider quarantine or reject after validating legitimate senders.",
      );
    const full =
      spf.length === 1 &&
      dmarc.length === 1 &&
      spfStrict &&
      ["quarantine", "reject"].includes(policy);
    const some = spf.length || dmarc.length;
    return C.result(
      full ? "passed" : some ? "warning" : "failed",
      full ? 10 : some ? 5 : 0,
      full
        ? "SPF and an enforcing DMARC policy found."
        : "Email authentication is missing, ambiguous, or not enforcing.",
      {
        spfRecords: spf.slice(0, 3),
        dmarcRecords: dmarc.slice(0, 3),
        recommendations,
        limitation:
          "Checks this exact hostname; organizational-domain fallback and full DNS policy evaluation are not performed.",
      },
    );
  }
}
if (typeof module !== "undefined") module.exports = EmailSecurityChecker;
