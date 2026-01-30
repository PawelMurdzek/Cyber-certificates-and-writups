# VIM Cheat Sheet
- **Vim Cheat Sheet**: [vim.rtorr.com](https://vim.rtorr.com/)
  - An interactive and comprehensive cheat sheet for VIM commands and shortcuts.
## Modes
- **Normal Mode**: `Esc` (Default mode for navigation)
- **Insert Mode**: `i` (insert before cursor), `a` (append after cursor), `o` (open new line below)
- **Visual Mode**: `v` (character), `V` (line), `Ctrl+v` (block)
- **Command Mode**: `:`

## Navigation (Normal Mode)
- `h` `j` `k` `l`: Left, Down, Up, Right
- `w` / `b`: Next word / Previous word
- `0` / `$`: Start of line / End of line
- `gg`: Top of file
- `G`: Bottom of file
- `:<line_number>`: Go to specific line (e.g., `:42`)
- `Ctrl+d` / `Ctrl+u`: Half page down / up

## Editing
- `u`: Undo
- `Ctrl+r`: Redo
- `x`: Delete character
- `dd`: Delete (cut) line
- `yy`: Yank (copy) line
- `p`: Paste after cursor
- `dw`: Delete word
- `cw`: Change word (delete and enter insert mode)
- `r`: Replace single character
- `.` : Repeat last command

## Search & Replace
- `/pattern`: Search forward
- `?pattern`: Search backward
- `n` / `N`: Next match / Previous match
- `:%s/old/new/g`: Replace all occurrences in file
- `:%s/old/new/gc`: Replace all with confirmation

## Saving & Exiting
- `:w`: Save
- `:q`: Quit
- `:wq` or `:x`: Save and Quit
- `:q!`: Quit without saving

## Visual Mode
- `>` / `<`: Indent / Outdent selection
- `y`: Yank selection
- `d`: Delete selection
- `~`: Toggle case