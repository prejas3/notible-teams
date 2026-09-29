# Notible Teams (test version)

Share one project with a few people. The project and everything filed under
it is encrypted on your computer before it goes to the Notible Teams server;
the server keeps only ciphertext and who is in which project.

Requires Notible 0.91.2 or newer.

## How to use

1. Settings → Plugins → Notible Teams → **Sign in with Google**. During the
   test only invited accounts can sign in.
2. **Share a project**: pick one of your projects.
3. Open the project's row → **Create invite code**, and send the code to one
   person, privately. It works once, for 24 hours, and it opens the project.
4. The other person: **Join with a code** → paste → Join.

Changes travel about once a minute, and ten seconds after you edit.

## What to expect

- If two people change the same note between syncs, the newest version stays
  and the other is kept next to it as "(conflict copy, name)".
- A note deleted by one person and edited by another comes back.
- A note moved out of the project stops being shared; others keep their copy.
- Removing someone stops their access to the server. What their computer
  already has stays there.
- Do not install plugins from other authors on a computer that is in a team:
  any installed plugin can read what this one can.

Design: `docs/superpowers/specs/2026-09-29-notible-teams-prototype-design.md`
in the Notible repository.
