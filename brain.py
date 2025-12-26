  # Build report object up front
    report = Report(title="Nullpeas Privilege Escalation Analysis")

    # Run interactive modules
    _interactive_modules(state, report)

    # 1) Analysis sections
    _append_analysis_sections_to_report(state, report)

    # 2) Offensive chaining engine section
    _append_offensive_chains_to_report(state, report)

    if report.sections:
        path = report.write()
        print(f"[+] Report written to: {path}")


if __name__ == "__main__":
    main()
