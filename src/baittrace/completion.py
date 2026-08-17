"""Shell completion scripts for the baittrace CLI.

Generated at runtime so rule IDs stay in sync with the loaded analyzers.
No third-party completion library: the output is plain bash, zsh, or fish.
"""

from __future__ import annotations

from collections.abc import Sequence

SHELLS = ("bash", "zsh", "fish")


def render(shell: str, *, rule_ids: Sequence[str], categories: Sequence[str]) -> str:
    """Return a completion script for ``shell``."""
    if shell == "bash":
        return _bash(rule_ids, categories)
    if shell == "zsh":
        return _zsh(rule_ids, categories)
    if shell == "fish":
        return _fish(rule_ids, categories)
    raise ValueError(f"unknown shell {shell!r}; choose from {', '.join(SHELLS)}")


def _join(values: Sequence[str]) -> str:
    return " ".join(values)


def _bash(rule_ids: Sequence[str], categories: Sequence[str]) -> str:
    rules = _join(rule_ids)
    cats = _join(categories)
    return f"""# baittrace bash completion
# eval "$(baittrace completion bash)"

_baittrace() {{
    local cur prev
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    local cmds="scan explain rules schema version init completion"
    local scan_opts="--format --fail-on --online --follow-redirects --redact"
    scan_opts+=" --config --rulepack --only --skip --no-plugins"
    scan_opts+=" --deterministic --width --no-color --color --no-unicode --help"
    local rules="{rules}"
    local cats="{cats}"

    if [[ ${{COMP_CWORD}} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${{cmds}} --help --version" -- "${{cur}}") )
        return
    fi

    local cmd="${{COMP_WORDS[1]}}"
    case "${{cmd}}" in
        scan)
            case "${{prev}}" in
                --format)
                    COMPREPLY=( $(compgen -W "text json" -- "${{cur}}") ); return ;;
                --fail-on)
                    local bands="benign suspicious high critical never"
                    COMPREPLY=( $(compgen -W "${{bands}}" -- "${{cur}}") )
                    return ;;
                --only|--skip)
                    COMPREPLY=( $(compgen -W "${{cats}}" -- "${{cur}}") ); return ;;
                --config|--rulepack|--width) return ;;
            esac
            if [[ "${{cur}}" == -* ]]; then
                COMPREPLY=( $(compgen -W "${{scan_opts}}" -- "${{cur}}") )
                return
            fi
            _baittrace_eml
            ;;
        explain)
            COMPREPLY=( $(compgen -W "${{rules}}" -- "${{cur}}") )
            ;;
        rules)
            if [[ "${{prev}}" == --category ]]; then
                COMPREPLY=( $(compgen -W "${{cats}}" -- "${{cur}}") )
            else
                COMPREPLY=( $(compgen -W "--category --help" -- "${{cur}}") )
            fi
            ;;
        init)
            COMPREPLY=( $(compgen -W "--global --force --help" -- "${{cur}}") )
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish --help" -- "${{cur}}") )
            ;;
        schema|version)
            COMPREPLY=( $(compgen -W "--help" -- "${{cur}}") )
            ;;
    esac
}}

_baittrace_eml() {{
    local files
    files=$(compgen -f -- "${{cur}}")
    local eml dir other
    eml="" dir="" other=""
    local f
    for f in ${{files}}; do
        if [[ -d "${{f}}" ]]; then
            dir+=" ${{f}}/"
        elif [[ "${{f}}" == *.eml ]]; then
            eml+=" ${{f}}"
        else
            other+=" ${{f}}"
        fi
    done
    COMPREPLY=( ${{eml}} ${{dir}} ${{other}} )
}}

complete -o filenames -F _baittrace baittrace
"""


def _zsh(rule_ids: Sequence[str], categories: Sequence[str]) -> str:
    rules = " ".join(f"'{rid}'" for rid in rule_ids)
    cats = " ".join(f"'{c}'" for c in categories)
    return f"""#compdef baittrace
# eval "$(baittrace completion zsh)"

_baittrace() {{
  local -a commands
  commands=(
    'scan:analyze one message and print a report'
    'explain:describe one rule in detail'
    'rules:list every rule this build can emit'
    'schema:print the JSON Schema for --format json'
    'version:print version, rulepack and analyzer inventory'
    'init:write a starter baittrace.toml'
    'completion:print a shell completion script'
  )

  local context state line
  typeset -A opt_args
  _arguments -C \\
    '(-h --help)'{{-h,--help}}'[show help]' \\
    '(- *)--version[show version]' \\
    '1:command:->cmds' \\
    '*::arg:->args'

  case $state in
    cmds)
      _describe -t commands 'command' commands
      ;;
    args)
      case $words[1] in
        scan)
          _arguments \\
            '--format[output format]:format:(text json)' \\
            '--fail-on[fail-on band]:band:(benign suspicious high critical never)' \\
            '--online[verify SPF/DKIM/DMARC via DNS]' \\
            '--follow-redirects[follow HTTP redirect chains]' \\
            '--redact[mask addresses and IPs]' \\
            '--config[path to baittrace.toml]:file:_files' \\
            '--rulepack[scoring pack]:pack:' \\
            '--only[run only this category]:category:({cats})' \\
            '--skip[skip this category]:category:({cats})' \\
            '--no-plugins[ignore third-party analyzers]' \\
            '--deterministic[byte-identical output]' \\
            '--width[report width in columns]:columns:' \\
            '--no-color[disable ANSI colour]' \\
            '--color[force ANSI colour]' \\
            '--no-unicode[use ASCII glyphs]' \\
            '1:message file:_files -g "*.eml"'
          ;;
        explain)
          _arguments '1:rule:({rules})'
          ;;
        rules)
          _arguments '--category[filter to one category]:category:({cats})'
          ;;
        init)
          _arguments '--global[write to XDG config dir]' '--force[overwrite existing file]'
          ;;
        completion)
          _arguments '1:shell:(bash zsh fish)'
          ;;
      esac
      ;;
  esac
}}

if (( $+functions[compdef] )); then
  compdef _baittrace baittrace
fi
"""


def _fish(rule_ids: Sequence[str], categories: Sequence[str]) -> str:
    lines = [
        "# baittrace fish completion",
        "# baittrace completion fish | source",
        "complete -c baittrace -e",
        "complete -c baittrace -f",
        "complete -c baittrace -n '__fish_use_subcommand' -a scan -d 'analyze one message'",
        "complete -c baittrace -n '__fish_use_subcommand' -a explain -d 'describe one rule'",
        "complete -c baittrace -n '__fish_use_subcommand' -a rules -d 'list every rule'",
        "complete -c baittrace -n '__fish_use_subcommand' -a schema -d 'print JSON Schema'",
        "complete -c baittrace -n '__fish_use_subcommand' -a version -d 'print version'",
        "complete -c baittrace -n '__fish_use_subcommand' -a init -d 'write starter config'",
        "complete -c baittrace -n '__fish_use_subcommand' -a completion -d 'print completions'",
        "complete -c baittrace -n '__fish_use_subcommand' -l help -d 'show help'",
        "complete -c baittrace -n '__fish_use_subcommand' -l version -d 'show version'",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan' -l format -xa 'text json'",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan'"
        " -l fail-on -xa 'benign suspicious high critical never'",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan' -l online",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan' -l follow-redirects",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan' -l redact",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan' -l config -r",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan' -l rulepack",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan'"
        f" -l only -xa '{_join(categories)}'",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan'"
        f" -l skip -xa '{_join(categories)}'",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan' -l no-plugins",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan' -l deterministic",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan' -l width",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan' -l no-color",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan' -l color",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan' -l no-unicode",
        "complete -c baittrace -n '__fish_seen_subcommand_from scan' -k -a"
        " '(__fish_complete_suffix .eml)'",
        f"complete -c baittrace -n '__fish_seen_subcommand_from explain' -a '{_join(rule_ids)}'",
        "complete -c baittrace -n '__fish_seen_subcommand_from rules'"
        f" -l category -xa '{_join(categories)}'",
        "complete -c baittrace -n '__fish_seen_subcommand_from init' -l global",
        "complete -c baittrace -n '__fish_seen_subcommand_from init' -l force",
        "complete -c baittrace -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'",
    ]
    return "\n".join(lines) + "\n"


__all__ = ["SHELLS", "render"]
