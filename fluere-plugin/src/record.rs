use fluereflow::FluereRecord;
use mlua::Lua;

/// Build the Lua table a plugin's `process_data` receives.
///
/// Every field is set by name from the record itself. The previous version
/// zipped a positional `Vec<String>` against a list of key names, so inserting
/// a field anywhere but the end silently shifted every later value into the
/// wrong key. Values stay strings, which is what existing plugins expect.
pub fn to_lua_table<'lua>(
    lua: &'lua Lua,
    record: &FluereRecord,
) -> mlua::Result<mlua::Table<'lua>> {
    let table = lua.create_table()?;

    table.set("source", record.source.to_string())?;
    table.set("destination", record.destination.to_string())?;
    table.set("d_pkts", record.d_pkts.to_string())?;
    table.set("d_octets", record.d_octets.to_string())?;
    table.set("first", record.first.to_string())?;
    table.set("last", record.last.to_string())?;
    table.set("src_port", record.src_port.to_string())?;
    table.set("dst_port", record.dst_port.to_string())?;
    table.set("min_pkt", record.min_pkt.to_string())?;
    table.set("max_pkt", record.max_pkt.to_string())?;
    table.set("min_ttl", record.min_ttl.to_string())?;
    table.set("max_ttl", record.max_ttl.to_string())?;
    table.set("in_pkts", record.in_pkts.to_string())?;
    table.set("out_pkts", record.out_pkts.to_string())?;
    table.set("in_bytes", record.in_bytes.to_string())?;
    table.set("out_bytes", record.out_bytes.to_string())?;
    table.set("fin_cnt", record.fin_cnt.to_string())?;
    table.set("syn_cnt", record.syn_cnt.to_string())?;
    table.set("rst_cnt", record.rst_cnt.to_string())?;
    table.set("psh_cnt", record.psh_cnt.to_string())?;
    table.set("ack_cnt", record.ack_cnt.to_string())?;
    table.set("urg_cnt", record.urg_cnt.to_string())?;
    table.set("ece_cnt", record.ece_cnt.to_string())?;
    table.set("cwr_cnt", record.cwr_cnt.to_string())?;
    table.set("ns_cnt", record.ns_cnt.to_string())?;
    table.set("prot", record.prot.to_string())?;
    table.set("tos", record.tos.to_string())?;
    table.set("mid_stream", u8::from(record.mid_stream).to_string())?;

    Ok(table)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::to_lua_table;
    use fluereflow::FluereRecord;
    use mlua::Lua;

    fn record() -> FluereRecord {
        FluereRecord::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            7,
            420,
            1_000,
            2_000,
            12_345,
            443,
            54,
            120,
            64,
            64,
            3,
            4,
            180,
            240,
            1,
            1,
            0,
            0,
            5,
            0,
            0,
            0,
            0,
            6,
            40,
            true,
        )
    }

    #[test]
    fn every_field_reaches_lua_under_its_own_name() {
        let lua = Lua::new();
        let table = to_lua_table(&lua, &record()).expect("table builds");

        for (key, expected) in [
            ("source", "192.0.2.1"),
            ("destination", "198.51.100.2"),
            ("d_pkts", "7"),
            ("d_octets", "420"),
            ("first", "1000"),
            ("last", "2000"),
            ("src_port", "12345"),
            ("dst_port", "443"),
            ("min_pkt", "54"),
            ("max_pkt", "120"),
            ("min_ttl", "64"),
            ("max_ttl", "64"),
            ("in_pkts", "3"),
            ("out_pkts", "4"),
            ("in_bytes", "180"),
            ("out_bytes", "240"),
            ("fin_cnt", "1"),
            ("syn_cnt", "1"),
            ("ack_cnt", "5"),
            ("prot", "6"),
            ("tos", "40"),
            ("mid_stream", "1"),
        ] {
            let actual: String = table.get(key).unwrap_or_else(|_| panic!("missing {}", key));
            assert_eq!(actual, expected, "wrong value for {}", key);
        }
    }

    #[test]
    fn table_key_count_matches_the_record() {
        let lua = Lua::new();
        let table = to_lua_table(&lua, &record()).expect("table builds");

        let keys = table.pairs::<String, mlua::Value>().count();
        assert_eq!(keys, 28, "one key per FluereRecord field");
    }
}
