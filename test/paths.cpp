#include "sys_call_test.h"
#include <gtest.h>
#include <algorithm>
#include "event_capture.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <event.h>
#include <Poco/Process.h>
#include <Poco/PipeStream.h>
#include <Poco/StringTokenizer.h>
#include <Poco/NumberFormatter.h>
#include <Poco/NumberParser.h>
#include <Poco/Path.h>
#include <list>
#include <cassert>

using namespace std;
using Poco::StringTokenizer;
using Poco::NumberFormatter;
using Poco::NumberParser;
using Poco::Path;

#define DATA "josephine"

class path_validator
{
public:
	path_validator(string filename, string bcwd)
	{
		update_cwd(filename, bcwd);
	}

	void update_cwd(string filename, string bcwd)
	{
		m_callnum = 0;
		m_filename = filename;

		Path pdt;
		pdt.parseDirectory(bcwd);

		Path pf;
		pf.parse(filename);
		if(pf.isAbsolute())
		{
			pdt.assign(pf);
		}
		else
		{
			pdt.append(pf);
		}

		Path pd(pdt.toString());
//printf("!!!!%s -- %s -- %s\n", pd.toString().c_str(), filename.c_str(), bcwd.c_str());
		m_scat = string("<f>") + pd.toString();

		m_scwd = bcwd;

		if(m_scwd[m_scwd.size() != '/'])
		{
			m_scwd += '/';
		}
	}

	void validate(sinsp_evt * e)
	{
		uint16_t type = e->get_type();
		sinsp_threadinfo* pinfo = e->get_thread_info(false);

		switch(m_callnum)
		{
		case 0:
			if(type == PPME_SYSCALL_OPEN_E)
			{
				m_callnum++;
			}

			break;
		case 1:
			if(type == PPME_SYSCALL_OPEN_X)
			{
				EXPECT_EQ(e->get_param_value_str("name", false), m_filename);
				EXPECT_EQ(m_scwd, pinfo->get_cwd());
				EXPECT_EQ(m_scat, e->get_param_value_str("fd"));
				m_fd = NumberParser::parse(e->get_param_value_str("fd", false));
				m_callnum++;
			}

			break;
		case 2:
			if(type == PPME_SYSCALL_WRITE_E)
			{
				int cfd = NumberParser::parse(e->get_param_value_str("fd", false));

				if(cfd == m_fd)
				{
					EXPECT_EQ(m_scat, e->get_param_value_str("fd"));
					EXPECT_EQ(NumberFormatter::format(sizeof(DATA) - 1), e->get_param_value_str("size"));
					m_callnum++;
				}
			}

			break;
		case 3:
			if(type == PPME_SYSCALL_WRITE_X)
			{
				EXPECT_EQ(NumberFormatter::format(sizeof(DATA) - 1), e->get_param_value_str("res"));
				EXPECT_EQ(m_scwd, pinfo->get_cwd());
				EXPECT_EQ(DATA, e->get_param_value_str("data"));
				m_callnum++;
			}

			break;
		default:
			break;
		}
	};

	int m_callnum;
	char m_bcwd[1024];
	int m_fd;
	string m_filename;
	string m_scwd;
	string m_scat;
};

TEST_F(sys_call_test, proc_mgmt)
{
	string filename = "test_tmpfile";
	char bcwd[1024];

	getcwd(bcwd, 1024);
	path_validator vldt(filename, bcwd);

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		unlink(vldt.m_filename.c_str());

		FILE* f = fopen(vldt.m_filename.c_str(), "w+");
		fwrite(DATA, sizeof(DATA) - 1, 1, f);
		fclose(f);

		unlink(vldt.m_filename.c_str());

	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		vldt.validate(param.m_evt);
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(4, vldt.m_callnum);
}

void testdir(string filename, string chdirtarget = "")
{
	char bcwd[1024];

	getcwd(bcwd, 1024);
	path_validator vldt(filename, bcwd);

	//
	// FILTER
	//
	event_filter_t aafilter = [&](sinsp_evt * evt)
	{
		int tid = getpid();
		return evt->get_tid() == tid;
//		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		if(chdirtarget != "")
		{
			char tcwd[1024];

			chdir(chdirtarget.c_str());

			getcwd(tcwd, 1024);
			vldt.update_cwd(filename, tcwd);
		}

		unlink(vldt.m_filename.c_str());

		FILE* f = fopen(vldt.m_filename.c_str(), "w+");

		if(f)
		{
			fwrite(DATA, sizeof(DATA) - 1, 1, f);
			fclose(f);
		}
		else
		{
			FAIL();
		}

		unlink(vldt.m_filename.c_str());

		if(chdirtarget != "")
		{
			chdir(bcwd);
		}
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		vldt.validate(param.m_evt);
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, aafilter);});

	EXPECT_EQ(4, vldt.m_callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// relative path-based tests
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, dir_path_1)
{
	testdir("./test_tmpfile");
}

TEST_F(sys_call_test, dir_path_2)
{
	testdir("../test_tmpfile");
}

TEST_F(sys_call_test, dir_path_3)
{
	testdir("/test_tmpfile");
}

TEST_F(sys_call_test, dir_path_4)
{
	testdir("//test_tmpfile");
}

TEST_F(sys_call_test, dir_path_5)
{
	testdir("///test_tmpfile");
}

TEST_F(sys_call_test, dir_path_6)
{
	testdir("////test_tmpfile");
}

TEST_F(sys_call_test, dir_path_7)
{
	testdir("//////////////////////////////test_tmpfile");
}

TEST_F(sys_call_test, dir_path_8)
{
	testdir("../test/test_tmpfile");
}

TEST_F(sys_call_test, dir_path_9)
{
	testdir("../test/../test/../test/../test/test_tmpfile");
}

TEST_F(sys_call_test, dir_path_10)
{
	testdir("/./test_tmpfile");
}

TEST_F(sys_call_test, dir_path_11)
{
	testdir("/../test_tmpfile");
}

TEST_F(sys_call_test, dir_path_12)
{
	testdir("/../../../../../../test_tmpfile");
}

TEST_F(sys_call_test, dir_path_13)
{
	testdir("../../../../../../test_tmpfile");
}

TEST_F(sys_call_test, dir_path_14)
{
	testdir("././././././test_tmpfile");
}

TEST_F(sys_call_test, dir_path_15)
{
	testdir(".././.././.././test_tmpfile");
}

TEST_F(sys_call_test, dir_path_16)
{
	int res = mkdir("./tmpdir", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0;

	if(res < 0 && res != EEXIST)
	{
		FAIL();
	}

	testdir("tmpdir/test_tmpfile");

	rmdir("./tmpdir");
}

TEST_F(sys_call_test, dir_path_17)
{
	int res = mkdir("./tmpdir", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0;
	if(res < 0 && res != EEXIST)
	{
		FAIL();
	}

	testdir("../test/tmpdir/test_tmpfile");

	rmdir("./tmpdir");
}

TEST_F(sys_call_test, dir_path_18)
{
	int res = mkdir("./tmpdir", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0;
	if(res < 0 && res != EEXIST)
	{
		FAIL();
	}

	testdir("./tmpdir/test_tmpfile");

	rmdir("./tmpdir");
}

TEST_F(sys_call_test, dir_path_19)
{
	int res = mkdir("./tmpdir", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0;
	if(res < 0 && res != EEXIST)
	{
		FAIL();
	}

	testdir("tmpdir/../tmpdir/../tmpdir/../tmpdir/../tmpdir/test_tmpfile");

	rmdir("./tmpdir");
}

/////////////////////////////////////////////////////////////////////////////////////
// chdir-based tests
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, dir_chdir_1)
{
	testdir("test_tmpfile", "./");
}

TEST_F(sys_call_test, dir_chdir_2)
{
	testdir("test_tmpfile", "../");
}

TEST_F(sys_call_test, dir_chdir_3)
{
	testdir("test_tmpfile", "/");
}

TEST_F(sys_call_test, dir_chdir_4)
{
	testdir("test_tmpfile", "//");
}

TEST_F(sys_call_test, dir_chdir_5)
{
	testdir("test_tmpfile", "///");
}

TEST_F(sys_call_test, dir_chdir_6)
{
	testdir("test_tmpfile", "////");
}

TEST_F(sys_call_test, dir_chdir_7)
{
	testdir("test_tmpfile", "//////////////////////////////");
}

TEST_F(sys_call_test, dir_chdir_8)
{
	testdir("test_tmpfile", "../test/");
}

TEST_F(sys_call_test, dir_chdir_9)
{
	testdir("test_tmpfile", "../test/../test/../test/../test");
}

TEST_F(sys_call_test, dir_chdir_10)
{
	testdir("test_tmpfile", "/./");
}

TEST_F(sys_call_test, dir_chdir_11)
{
	testdir("test_tmpfile", "/..");
}

TEST_F(sys_call_test, dir_chdir_12)
{
	testdir("test_tmpfile", "/../../../../../../");
}

TEST_F(sys_call_test, dir_chdir_13)
{
	testdir("test_tmpfile", "../../../../../..");
}

TEST_F(sys_call_test, dir_chdir_14)
{
	testdir("test_tmpfile", "././././././");
}

TEST_F(sys_call_test, dir_chdir_15)
{
	testdir("test_tmpfile", ".././.././.././");
}

TEST_F(sys_call_test, dir_chdir_16)
{
	int res = mkdir("./tmpdir", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0;

	if(res < 0 && res != EEXIST)
	{
		FAIL();
	}

	testdir("test_tmpfile", "tmpdir");

	rmdir("./tmpdir");
}

TEST_F(sys_call_test, dir_chdir_17)
{
	int res = mkdir("./tmpdir", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0;
	if(res < 0 && res != EEXIST)
	{
		FAIL();
	}

	testdir("../test/tmpdir/test_tmpfile");

	rmdir("./tmpdir");
}

TEST_F(sys_call_test, dir_chdir_18)
{
	int res = mkdir("./tmpdir", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0;
	if(res < 0 && res != EEXIST)
	{
		FAIL();
	}

	testdir("./tmpdir/test_tmpfile");

	rmdir("./tmpdir");
}

TEST_F(sys_call_test, dir_chdir_19)
{
	int res = mkdir("./tmpdir", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) < 0;
	if(res < 0 && res != EEXIST)
	{
		FAIL();
	}

	testdir("tmpdir/../tmpdir/../tmpdir/../tmpdir/../tmpdir/test_tmpfile");

	rmdir("./tmpdir");
}

/////////////////////////////////////////////////////////////////////////////////////
// chdir/getcwd
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, dir_getcwd)
{
	int callnum = 0;
	char dir0[] = "./";
	char dir1[] = "..";
	char dir2[] = "/";
	char dir3[] = "usr";
	char dir4[] = "usr";
	char cwd_ori[256];
	char cwd0[256];
	char cwd1[256];
	char cwd2[256];
	char cwd3[256];
	char cwd4[256];
	char cwd5[256];

	getcwd(cwd_ori, 256);

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		chdir(dir0);
		getcwd(cwd0, 256);

		chdir(dir1);
		getcwd(cwd1, 256);

		chdir(dir2);
		getcwd(cwd2, 256);

		chdir(dir3);
		getcwd(cwd3, 256);

		chdir(dir4);
		getcwd(cwd4, 256);

		chdir(cwd_ori);
		getcwd(cwd5, 256);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		sinsp_threadinfo* pinfo = e->get_thread_info(false);

		if(type == PPME_SYSCALL_CHDIR_E)
		{
			callnum++;
		}
		else if(type == PPME_SYSCALL_CHDIR_X)
		{
			string cdir;
			string cdir1;
			string adir;

			switch(callnum)
			{
			case 1:
				EXPECT_EQ("0", e->get_param_value_str("res"));
				cdir = string(cwd0);
				adir = string(dir0);
				break;
			case 3:
				EXPECT_EQ("0", e->get_param_value_str("res"));
				cdir = string(cwd1);
				adir = string(dir1);
				break;
			case 5:
				EXPECT_EQ("0", e->get_param_value_str("res"));
				cdir = string(cwd2);
				adir = string(dir2);
				break;
			case 7:
				EXPECT_EQ("0", e->get_param_value_str("res"));
				cdir = string(cwd3);
				adir = string(dir3);
				break;
			case 9:
				EXPECT_NE("0", e->get_param_value_str("res"));
				cdir = string(cwd3);
				adir = string(dir4);
				break;
			case 11:
				EXPECT_EQ("0", e->get_param_value_str("res"));
				cdir = string(cwd_ori);
				adir = string(cwd_ori);
				break;
			default:
				FAIL();
				break;
			}

			EXPECT_EQ(adir, e->get_param_value_str("path"));

			//
			// pinfo->get_cwd() contains a / at the end of the directory
			//
			if(cdir != "/")
			{
				cdir1 = cdir + "/";
			}
			else
			{
				cdir1 = cdir;
			}
			EXPECT_EQ(cdir1, pinfo->get_cwd());

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(12, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// fchdir
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, dir_fchdir)
{
	int callnum = 0;
	char dir0[] = "./";
	char dir1[] = "..";
	char dir2[] = "/";
	char dir3[] = "usr";
	char cwd_ori[256];
	char cwd0[256];
	char cwd1[256];
	char cwd2[256];
	char cwd3[256];
	char cwd4[256];
	char cwd5[256];

	getcwd(cwd_ori, 256);

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		return m_tid_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		int fd;

		fd = open(dir0, O_RDONLY);
		if(fd < 0)
		{
			FAIL();
		}
		fchdir(fd);
		getcwd(cwd0, 256);
		close(fd);

		fd = open(dir1, O_RDONLY);
		if(fd < 0)
		{
			FAIL();
		}
		fchdir(fd);
		getcwd(cwd1, 256);
		close(fd);

		fd = open(dir2, O_RDONLY);
		if(fd < 0)
		{
			FAIL();
		}
		fchdir(fd);
		getcwd(cwd2, 256);
		close(fd);

		fd = open(dir3, O_RDONLY);
		if(fd < 0)
		{
			FAIL();
		}
		fchdir(fd);
		getcwd(cwd3, 256);
		close(fd);

		fchdir(12345);
		getcwd(cwd4, 256);
		close(fd);

		fd = open(cwd_ori, O_RDONLY);
		if(fd < 0)
		{
			FAIL();
		}
		fchdir(fd);
		getcwd(cwd5, 256);
		close(fd);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		sinsp_threadinfo* pinfo = e->get_thread_info(false);

		if(type == PPME_SYSCALL_FCHDIR_E)
		{
			string adir;

			switch(callnum)
			{
			case 0:
				adir = string("<f>") + string(cwd0);
				break;
			case 2:
				adir = string("<f>") + string(cwd1);
				break;
			case 4:
				adir = string("<f>") + string(cwd2);
				break;
			case 6:
				adir = string("<f>") + string(cwd3);
				break;
			case 8:
				adir = "12345";
				break;
			case 10:
				adir = string("<f>") + string(cwd_ori);
				break;
			default:
				FAIL();
				break;
			}

			EXPECT_EQ(adir, e->get_param_value_str("fd"));

			callnum++;
		}
		else if(type == PPME_SYSCALL_FCHDIR_X)
		{
			string cdir;
			string cdir1;

			switch(callnum)
			{
			case 1:
				EXPECT_EQ("0", e->get_param_value_str("res"));
				cdir = string(cwd0);
				break;
			case 3:
				EXPECT_EQ("0", e->get_param_value_str("res"));
				cdir = string(cwd1);
				break;
			case 5:
				EXPECT_EQ("0", e->get_param_value_str("res"));
				cdir = string(cwd2);
				break;
			case 7:
				EXPECT_EQ("0", e->get_param_value_str("res"));
				cdir = string(cwd3);
				break;
			case 9:
				EXPECT_NE("0", e->get_param_value_str("res"));
				cdir = string(cwd3);
				break;
			case 11:
				EXPECT_EQ("0", e->get_param_value_str("res"));
				cdir = string(cwd_ori);
				break;
			default:
				FAIL();
				break;
			}

			//
			// pinfo->get_cwd() contains a / at the end of the directory
			//
			if(cdir != "/")
			{
				cdir1 = cdir + "/";
			}
			else
			{
				cdir1 = cdir;
			}
			
			EXPECT_EQ(cdir1, pinfo->get_cwd());

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(12, callnum);
}

#ifdef __x86_64__
TEST_F(sys_call_test32, proc_mgmt)
{
	string filename = "test_tmpfile";
	char bcwd[1024];

	getcwd(bcwd, 1024);
	path_validator vldt(filename, bcwd);

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt * evt)
	{
		auto tinfo = evt->get_thread_info(false);
		return tinfo && tinfo->m_comm == "test_helper_32" && m_proc_started_filter(evt);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector)
	{
		proc test_proc("./test_helper_32", {"proc_mgmt" , filename });
		auto handle = start_process(&test_proc);
		get<0>(handle).wait();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		vldt.validate(param.m_evt);
	};

	ASSERT_NO_FATAL_FAILURE({event_capture::run(test, callback, filter);});

	EXPECT_EQ(4, vldt.m_callnum);
}


#endif