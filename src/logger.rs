use colored::Colorize;
use log::{Record, Level, Metadata, SetLoggerError, LevelFilter};

struct SimpleLogger {
    pub max_level: Level,
}

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.max_level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let prefix = match record.level() {
                Level::Error => "error: ".bright_red().bold(),
                Level::Warn => "warn: ".bright_yellow().bold(),
                Level::Info => "".into(),
                Level::Debug => "debug: ".bright_cyan().bold(),
                Level::Trace => "trace: ".bright_magenta().bold(),
            };

            println!("{}{}", prefix, record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: SimpleLogger = SimpleLogger { max_level: log::Level::Debug };

pub fn init() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(LevelFilter::Info))
}
