# Contributing to this Plugin

Hello! Contributions are essential to keep this plugin alive. I would like to
keep it as easy as possible to contribute changes. There are a few guidelines
that I need contributors to follow so that all of us can benefit from quality
control and quality documentation.

## Table of Contents

1. [Getting Started](#getting-started)
1. [Initial Github Commit and Pull Request](#initial-github-commit-and-pull-request)
  1. [New Branch and Changes](#new-branch-and-changes)
  1. [Summarize Changes](#summarize-changes)
  1. [Stage, Commit, and Push Changes](#stage-commit-and-push-changes)
  1. [Cleanup](#cleanup)
1. [Amend Existing Commit](#amend-existing-commit)
  1. [Commit Message Only](#commit-message-only)
  1. [Commit Files Only](#commit-files-only)
  1. [Commit Message and Files](#commit-message-and-files)

## Getting Started

First, review and understand the following diagram:

[![Plugin Workflow](https://raw.githubusercontent.com/greenpau/ndmtk/master/docs/_static/images/ndmtk.code.submission.workflow.png "Network Automation Workflow")](https://raw.githubusercontent.com/greenpau/ndmtk/master/docs/_static/images/ndmtk.code.submission.workflow.png)

The diagram describes [Git Forking Workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/forking-workflow).
That is the code management workflow for this repository.

Next, a contributor must have a GitHub account.

After that, the contributor forks this repository (thereafter **upsteam**) by
clicking `Fork` button on the top-right of this page. The forked repository
(thereafter **origin**) becomes a part of the contributor's Github account.

Then, the contributor makes a local copy of the forked repository (thereafter
**local**).

```
mkdir -p ~/dev && cd ~/dev && \
 git clone git@github.com:CONTRIBUTOR_GITHUB_HANDLE/ndmtk.git
```

The contributor creates a reference to **upstream** on his or her localhost:

```
git remote add upstream git@github.com:greenpau/ndmtk.git
```

Thereafter, the contributor follows the Initial Github Commit and Pull Request
guidance.

:warning: In some instances, a user's fork does not sync with its **upstream**
automatically. In those cases, the user must manually sync the fork:

```
git checkout master
git remote add upstream git://github.com/greenpau/ndmtk.git
git fetch upstream
git merge upstream/master master
git push
```

:arrow_up: [Back to top](#top)

*****

## Initial Github Commit and Pull Request

### New Branch and Changes

First, switch to **local**/`master` branch and create a new one, e.g. `mychangebranch`:

```
git checkout master
git checkout -b mychangebranch
```

Next, upload the newly created branch to **origin**:

```
git push -u origin mychangebranch
```

Then, make changes to existing files, add new files, and/or delete old files.

#### Patching

A developer may change the plugin's code directly, inside `lib/python/site-packages`.
Later, the developer may decide to submit a patch. The below are the instructions
to create a patch.

Create a diff file, where `/home/greenpau/github.com/greenpau/ndmtk/ndmtk` is intact
source code directory and the `/lib/...` contains modified code:

```
diff -aNur -x '*.pyc' ~/github.com/greenpau/ndmtk/ndmtk /lib/python/site-packages/ndmtk > ~/ndmtk.patch
```

Then, create a new branch and apply the patch:

```
cd ~/github.com/greenpau/ndmtk/ndmtk
git checkout master
git checkout -b patch001
git push -u origin patch001
patch -s -p0 < ~/ndmtk.patch
```

:arrow_up: [Back to top](#top)

*****

### Summarize Changes

All commits must have proper commit message.

A commit message's subject line must conform to the following rules:
* The first line of each commit message is a subject
* A subject line MUST be less than 87 characters long
* A subject line MUST not terminate with a period (`.`)
* A subject line MUST start with a change indicator followed by a colon (`:`).
  The list of indicators is limited to:
  - `docs`: when making changes to documentation files, e.g. `README.md`
  - `ci`: when making changes to continuous integration test harness
  - `unittest`: when makeing changes to unit tests in `tests`
  - `plugin`: when making changes to this plugin
  - `docker`: when making changes to `Dockerfile`
  - `various`: default catch-all

Next, a commit message's body must contain the following mandatory sections:

1. `Before this commit`
2. `After this commit`
3. `Smoke-test`

Additionally, the body may contain the following sections:

1. `Resolves`
2. `Partial Resolution`
3. `See also`
4. `Links`
5. `More info`

The following rules apply to the body of a commit message:

* The sections are separated by a blank line
* A colon sign (`:`) MUST follow a section's title
* A line MUST not exceed 87 characters limit. This does not apply to `Links` or
  `More info` sections
* The `Resolves` section MUST be used ONLY when a PR resolves an issue completely
* If a PR addresses an issue partially, then use `Partial Resolution` section
* The `See also` section may be used to create an additional reference
* The `Resolves`, `Partial Resolution`, `See also` MUST contain links
  to valid references. Each of the links must be separated by a comma and a
  space (`, `)
* The `More info` section may be used to provide additional relevant information

The `Links` section must contain a list of valid links or references, e.g.:

```
  - Text reference
  - [HTTP link](http://google.com/)
```

For example, a commit message may look like this:

```
docs: add CONTRIBUTING.md file

Before this commit: the repository has no guidance related to open-source
contributions.

After this commit: the guidance is in `CONTRIBUTING.md` file.

Smoke-test: run manual tests in the absense of proper test harness
```

:arrow_up: [Back to top](#top)

*****

### Stage, Commit, and Push Changes

Add newly created, modified files to staging area:

```
git add .
```

Next, commit the files:

```
git commit
```

Next, paste the previously created commit message and save with `vim`'s `:wq`.

At this point, your **local** `mychangebranch` branch is behind **origin**
`mychangebranch` branch by 1 commit.

```
$ git status
# On branch mychangebranch
# Your branch is ahead of 'origin/mychangebranch' by 1 commit.
#   (use "git push" to publish your local commits)
#
nothing to commit, working directory clean
$
```

Finally, push **local** `mychangebranch` branch to **origin** `mychangebranch`
branch.

```
git push
```

Then, go to your **origin** `mychangebranch` branch in Github and create a
Pull Request.

:arrow_up: [Back to top](#top)

*****

### Cleanup

If:

- your PR was merged, delete local branch only (the remote branch was deleted
  by the person merging your branch):

```
git branch -d mychangebranch
```

- your PR was rejected or you want to remove it, delete both local and remote
  branches:

```
git branch -d mychangebranch
git push origin --delete mychangebranch
```

:arrow_up: [Back to top](#top)

*****

## Amend Existing Commit

Inevitably, a contributor would have the need to modify an existing commit or
pull request. When that happens, the contributor likely has an issue with
one of the following:

* Commit Message Only
* Commit Files Only
* Commit Message and Files

In all of the cases, when the contributor re-pushes commits, the Pull Request
associated with the commits receives new information. In turn, it forces to
re-run all of the associated continious integration tests.

:arrow_up: [Back to top](#top)

*****

### Commit Message Only

In this case, the contributor should run the following command to amend
a commit message:

```
git commit --amend
```

Once amended, the contributor must re-push the commit:

```
git push -f
```

:arrow_up: [Back to top](#top)

*****

### Commit Files Only

In this case, a contributor should follow these steps:

1. Create another commit in the same branch
2. Merge the newly created commit with one before it using `f` (`fixup`)
3. Re-push the newly merged commit with `-f` flag set.

First, edit a file, stage it, and re-commit it:

```
vim CONTRIBUTING.md
git add CONTRIBUTING.md
git commit -m 'commit message is not used'
```

Second, rebase the commit:

```
git rebase -i HEAD~2
```

The above command merges the two last commits (`HEAD~2`) in the branch:

```
pick a4ccfe8 docs: add CONTRIBUTING.md file
pick abcdef2 commit message is not used
```

In the `vim` editor window, the contributor must replace the word `pick`
for the second commit (e.g. `abcdef2`) with the letter `f` or the word
`fixup`.

```
pick a4ccfe8 docs: add CONTRIBUTING.md file
f abcdef2 commit message is not used
```

Then, the contributor saves the work with `:wq`.

Once completed, the contributor no longer has the two commit IDs in its
log (see `git log`). Instead, there is a single new commit ID with the
commit message from the `a4ccfe8` commit and the contents of `abcdef2`
commit.

Finally, the contributor must re-push the commit.

```
git push -f
```

:arrow_up: [Back to top](#top)

*****

### Commit Message and Files

In this case, a contributor should follow these steps:

1. Create another commit in the same branch
2. Merge the newly created commit with one before it using `s` (`squash`)
3. Re-push the newly merged commit with `-f` flag set.

First, edit a file, stage it, and re-commit it:

```
vim CONTRIBUTING.md
git add CONTRIBUTING.md
git commit -m 'commit message will be used'
```

Second, rebase the commit:

```
git rebase -i HEAD~2
```

The above command merges the two last commits (`HEAD~2`) in the branch:

```
pick a4ccfe8 docs: add CONTRIBUTING.md file
pick abcdef2 commit message will be used
```

In the `vim` editor window, the contributor must replace the word `pick`
for the second commit (e.g. `abcdef2`) with the letter `s` or the word
`squash`.

```
pick a4ccfe8 docs: add CONTRIBUTING.md file
s abcdef2 commit message will be used
```

Then, the contributor saves the work with `:wq`.

Unlike with the previous scenario, the contirubtor is given a `vim` editor
window once again. In the window, the contributor has the commit messages
from both commits. One from `a4ccfe8` commit and another one from `abcdef2`
commit.

The contributor must use the editor to delete the existing commit messages
and create a new one. Once completed, the contributor no longer has the
two commit IDs in its log (see `git log`). Instead, there is a single new
commit ID with new commit message.

Finally, the contributor must re-push the commit.

```
git push -f
```

:arrow_up: [Back to top](#top)

*****
