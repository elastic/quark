/*
 * This code is stashed in the end of manpage.h
 */
static void
display_man(void)
{
	int	fd, status;
	char	template[] = "/tmp/quark-man-display.XXXXXX";
	pid_t	pid;

	fd = mkstemp(template);
	if (fd == -1)
		err(1, "mkstemp");
	if (qwrite(fd, manpage_bin, sizeof(manpage_bin)) != 0)
		err(1, "qwrite");
	close(fd);

	if ((pid = fork()) == -1)
		err(1, "fork");

	/* child */
	if (pid == 0)
		exit(execlp("man", "man", template, NULL));
	/* parent */
	if (waitpid(pid, &status, 0) == -1)
		err(1, "waitpid");
	if (unlink(template) != 0)
		warn("unlink");
	if (WIFEXITED(status))
		exit(WEXITSTATUS(status));

	exit(1);
}
